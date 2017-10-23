""" Store packages in S3 """
import datetime
import logging
import posixpath
from contextlib import contextmanager
from hashlib import md5
from urllib import urlopen, quote

import boto3 as boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pyramid.httpexceptions import HTTPFound
from pyramid.settings import asbool

from pypicloud.models import Package
from pypicloud.util import parse_filename, getdefaults
from .base import IStorage

LOG = logging.getLogger(__name__)


class S3Storage(IStorage):
    """ Storage backend that uses S3 """
    test = False

    def __init__(self, request=None, bucket=None, expire_after=None,
                 bucket_prefix=None, prepend_hash=None, redirect_urls=None,
                 use_sse=False, addressing_style=None,
                 **kwargs):
        super(S3Storage, self).__init__(request, **kwargs)
        self.bucket = bucket
        self.expire_after = expire_after
        self.bucket_prefix = bucket_prefix
        self.prepend_hash = prepend_hash
        self.redirect_urls = redirect_urls
        self.use_sse = use_sse
        self.addressing_style = addressing_style

    @classmethod
    def configure(cls, settings):
        kwargs = super(S3Storage, cls).configure(settings)
        kwargs['expire_after'] = int(getdefaults(settings, 'storage.expire_after', 'aws.expire_after', 60 * 60 * 24))
        kwargs['bucket_prefix'] = getdefaults(settings, 'storage.prefix', 'aws.prefix', '')
        kwargs['addressing_style'] = getdefaults(settings, 'storage.addressing_style', 'aws.addressing_style', 'auto')
        kwargs['prepend_hash'] = asbool(getdefaults(settings, 'storage.prepend_hash', 'aws.prepend_hash', True))

        access_key = getdefaults(settings, 'storage.access_key', 'aws.access_key', None)
        secret_key = getdefaults(settings, 'storage.secret_key', 'aws.secret_key', None)

        kwargs['use_sse'] = asbool(
            getdefaults(settings, 'storage.server_side_encryption', 'aws.server_side_encryption', False)
        )

        kwargs['redirect_urls'] = asbool(settings.get('storage.redirect_urls', False))

        location = settings.get('storage.region', 'us-west-1')
        s3conn = boto3.resource(
            's3',
            region_name=location,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(s3={'addressing_style': kwargs['addressing_style']}),
        )

        aws_bucket = getdefaults(settings, 'storage.bucket', 'aws.bucket', None)

        if aws_bucket is None:
            raise ValueError("You must specify the 'storage.bucket'")
        try:
            s3conn.meta.client.head_bucket(Bucket=aws_bucket)
            bucket = boto3.resource('s3').Bucket(aws_bucket)
        except ClientError as e:
            if e.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404:
                LOG.info("Creating S3 bucket %s in region %s", aws_bucket, location)

                s3conn.meta.client.create_bucket(
                    Bucket=aws_bucket,
                    CreateBucketConfiguration={'LocationConstraint': location}
                )
                bucket = boto3.resource('s3').Bucket(aws_bucket)
            else:
                raise e

        kwargs['bucket'] = bucket
        return kwargs

    def calculate_path(self, package):
        """ Calculates the path of a package """
        path = package.name + '/' + package.filename

        if self.prepend_hash:
            m = md5()
            m.update(package.filename)
            prefix = m.digest().encode('hex')[:4]
            path = prefix + '/' + path

        return path

    def get_path(self, package):
        """ Get the fully-qualified bucket path for a package """
        if 'path' not in package.data:
            filename = self.calculate_path(package)
            package.data['path'] = self.bucket_prefix + filename

        return package.data['path']

    def list(self, factory=Package):
        keys = self.bucket.objects.all()
        for key in keys:
            # Boto doesn't send down metadata from bucket.list()
            # so we are forced to retrieve each key individually.

            obj = key.Object()

            filename = posixpath.basename(obj.key)
            name = obj.metadata.get('name')
            version = obj.metadata.get('version')
            summary = obj.metadata.get('summary')

            # We used to not store metadata. This is for backwards
            # compatibility
            if name is None or version is None:
                try:
                    name, version = parse_filename(filename)
                except ValueError:
                    LOG.warning("S3 file %s has no package name", key.key)
                    continue

            last_modified = key.last_modified

            pkg = factory(name, version, filename, last_modified, summary,
                          path=key.key)

            yield pkg

    def _generate_url(self, package):
        """ Generate a signed url to the S3 file """
        url = self.bucket.meta.client.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': self.bucket.name,
                'Key': self.get_path(package)
            }
        )

        return url

    def get_url(self, package):
        if self.redirect_urls:
            return super(S3Storage, self).get_url(package)
        else:
            return self._generate_url(package)

    def download_response(self, package):
        return HTTPFound(location=self._generate_url(package))

    def upload(self, package, data):
        metadata = {
            'name': package.name,
            'version': package.version,
        }

        if package.summary:
            metadata['summary'] = package.summary

        self.bucket.put_object(
            Key=self.get_path(package),
            Metadata=metadata,
            Body=data
        )

    def delete(self, package):
        path = self.get_path(package)

        self.bucket.delete_objects(
            Delete={
                'Objects': [{
                    'Key': path
                }]
            }
        )

    @contextmanager
    def open(self, package):
        url = self._generate_url(package)
        handle = urlopen(url)
        try:
            yield handle
        finally:
            handle.close()


class CloudFrontS3Storage(S3Storage):
    """ Storage backend that uses S3 and CloudFront """

    def __init__(self, request=None, bucket=None, expire_after=None, bucket_prefix=None,
                 prepend_hash=None, cloud_front_domain=None, cloud_front_key_file=None,
                 cloud_front_key_string=None, cloud_front_key_id=None, **kwargs):
        super(CloudFrontS3Storage, self).__init__(request, bucket, expire_after, bucket_prefix, prepend_hash, **kwargs)
        self.cloud_front_domain = cloud_front_domain
        self.cloud_front_key_file = cloud_front_key_file
        self.cloud_front_key_id = cloud_front_key_id
        self.cloud_front_key_string = cloud_front_key_string

        self.distribution = boto3.client('cloudfront')

    @classmethod
    def configure(cls, settings):
        kwargs = super(CloudFrontS3Storage, cls).configure(settings)
        kwargs['cloud_front_domain'] = getdefaults(settings, 'storage.cloud_front_domain', 'aws.cloud_front_domain', '')
        kwargs['cloud_front_key_file'] = getdefaults(settings, 'storage.cloud_front_key_file',
                                                     'aws.cloud_front_key_file', None)
        kwargs['cloud_front_key_string'] = getdefaults(settings, 'storage.cloud_front_key_string',
                                                       'aws.cloud_front_key_string', None)
        kwargs['cloud_front_key_id'] = getdefaults(settings, 'storage.cloud_front_key_id', 'aws.cloud_front_key_id', '')

        return kwargs

    def _generate_url(self, package):
        """ Get the fully-qualified CloudFront path for a package """

        def rsa_signer(message):
            with open(self.cloud_front_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1())
            signer.update(message)

            return signer.finalize()

        path = self.calculate_path(package)
        url = self.cloud_front_domain + '/' + quote(path)

        if self.cloud_front_key_file or self.cloud_front_key_string:
            cloudfront_signer = CloudFrontSigner(self.cloud_front_key_id, rsa_signer)

            expire_date = datetime.datetime.now() + datetime.timedelta(hours=1)

            # Create a signed url that will be valid until the specfic expiry date
            # provided using a canned policy.
            return cloudfront_signer.generate_presigned_url(url, date_less_than=expire_date)
        else:
            return super(CloudFrontS3Storage, self)._generate_url(package)
