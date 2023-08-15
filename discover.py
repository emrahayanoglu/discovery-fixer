"""Device specific configuration discovery."""
import logging
import os
import re
import time

from rad.configuration import Configuration, DeviceConfiguration
from cryptography import x509


class DeviceConfigurationDiscovery():
    """Implementing discovery of the device configuration."""

    log = logging.getLogger('DeviceConfigurationDiscovery')

    def discover(self, configuration: Configuration) -> DeviceConfiguration:
        """Discover and build device configuration.

        Returns:
            DeviceConfiguration: Discovered device configuration
        """
        pem_path = configuration.device.device_certificate
        self.log.info(f'Discovering device configuration from certificate file: {pem_path}')
        self.ensure_file_exists(pem_path)

        device_cn = self.resolve_device_cn(pem_path)
        self.log.info(f'Resolved device CN: {device_cn}')

        system_id = self.resolve_system_id(pem_path)
        country, env = system_id.split(' ')
        self.log.info(f'Resolved system ID: {system_id}, Country {country}, Environment {env}')

        attr_name = f'base_{env.lower()}_{country.lower()}'
        base_domain = configuration.device.__dict__.get(attr_name, configuration.device.base_p_zz)
        self.log.info(f'Resolved base domain: {base_domain}')

        result = DeviceConfiguration()
        result.device_cn = device_cn
        result.base_domain = base_domain
        result.device_certificate = configuration.device.device_certificate
        result.device_certificate_key = configuration.device.device_certificate_key
        result.ca_certificate = configuration.device.ca_certificates

        self.log.info('Device configuration discovered sucessfully.')
        return result


    @classmethod
    def ensure_file_exists(cls, path: str, num_retries: int = 24*60, retry_delay: int = 60):
        """Ensure that a given file exists by waiting.

        Args:
            path (str): Path to the file
            num_retries (int, optional): Number of retries. Defaults to 100.
            retry_delay (int, optional): Wait delay (seconds) before retrying
                file existence. Defaults to 60.

        Raises:
            FileNotFoundError: If the file still does not exists after
                specified retries
        """
        while True:
            if os.path.exists(path):
                return
            cls.log.fatal(f'Unable to read device configuration. File does not exist: {path}')
            if num_retries <= 0:
                break
            num_retries = num_retries - 1
            time.sleep(retry_delay)
        raise FileNotFoundError(path)

    @classmethod
    def resolve_device_cn(cls, path: str) -> str:
        """Read a .pem device certificate and try to resolve the corresponding device CN.

        Args:
            path (str): Path to a device .pem file

        Raises:
            EOFError: If the subject line cannot be found
            ValueError: if the subject line has an unexpected format

        Returns:
            str: The device CN
        """
        with open(path, mode='rb') as fd:
            cert = x509.load_pem_x509_certificate(fd.read())
            common_names = cert.subject.get_attributes_for_oid(oid=x509.NameOID.COMMON_NAME)
            if len(common_names) == 0:
                raise ValueError("NO CN Defined on Subject Side!")
            return common_names[0].value

    @classmethod
    def resolve_system_id(cls, path: str) -> str:
        """Read a .pem device certificate and try to resolve the corresponding system ID.

        Args:
            path (str): Path to a device .pem file

        Raises:
            EOFError: If the issuer line cannot be found
            ValueError: if the issuer line has an unexpected format

        Returns:
            str: The device system ID (country code like)
        """
        with open(path, mode='rb') as fd:
            cert = x509.load_pem_x509_certificate(fd.read())
            common_names = cert.issuer.get_attributes_for_oid(oid=x509.NameOID.COMMON_NAME)
            if len(common_names) == 0:
                raise ValueError("NO CN Defined on Issuer Side!")
            matcher = re.compile(r'CN = "?\w+\s?\w*\s?\w*\s?\w*\s? (\w\w \w-).*"?')
            match = matcher.match("CN = {}".format(common_names[0].value))
            if not match:
                raise ValueError("No Country Code Defined in Proper Way")
            return match.group(1)[0:4]