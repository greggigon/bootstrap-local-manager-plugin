import os
import urllib
import json
import pkgutil
import tarfile
import tempfile
from time import sleep, time
from StringIO import StringIO

import jinja2
import fabric
import fabric.api
from fabric.operations import local as run_local

from cloudify import ctx
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError
from cloudify_cli import constants

PROVIDER_RUNTIME_PROPERTY = 'provider'
MANAGER_IP_RUNTIME_PROPERTY = 'manager_ip'
MANAGER_USER_RUNTIME_PROPERTY = 'manager_user'
MANAGER_KEY_PATH_RUNTIME_PROPERTY = 'manager_key_path'
DEFAULT_REMOTE_AGENT_KEY_PATH = '~/.ssh/agent_key.pem'
REST_PORT = 'rest_port'

DEFAULT_CLOUDIFY_HOME_DIR = '~/cloudify'
HOST_SSL_CERTIFICATE_PATH = '~/cloudify/server.crt'
HOST_SSL_PRIVATE_KEY_PATH = '~/cloudify/server.key'

DEFAULT_SECURITY_LOG_FOLDER = '/var/log/cloudify'
DEFAULT_SECURITY_LOG_FILE = DEFAULT_SECURITY_LOG_FOLDER \
                            + "/rest-security-audit.log"
DEFAULT_SECURITY_LOG_LEVEL = 'INFO'
DEFAULT_SECURITY_LOG_FILE_SIZE_MB = 100
DEFAULT_SECURITY_LOG_FILES_BACKUP_COUNT = 20
DEFAULT_SECURITY_MODE = False
DEFAULT_DOCKER_PATH = 'docker'
DEFAULT_ELASTICSEARCH_HOST = 'localhost'
DEFAULT_ELASTICSEARCH_PORT = 9200

lgr = None


@operation
def creation_validation(cloudify_packages, **kwargs):
    if not isinstance(cloudify_packages, dict):
        raise NonRecoverableError('"cloudify_packages" must be a '
                                  'dictionary property')
    docker_packages = cloudify_packages.get('docker')

    if not docker_packages or not isinstance(docker_packages, dict):
        raise NonRecoverableError(
            '"docker" must be a non-empty dictionary property under '
            '"cloudify_packages"')

    packages_urls = docker_packages.values()
    agent_packages = cloudify_packages.get('agents', {})
    if not isinstance(agent_packages, dict):
        raise NonRecoverableError('"cloudify_packages.agents" must be a '
                                  'dictionary property')

    packages_urls.extend(agent_packages.values())
    for package_url in packages_urls:
        _validate_package_url_accessible(package_url)


@operation
def stop_manager_container(docker_path='docker', use_sudo=False, **kwargs):
    _run_command('{0} stop cfy'.format(docker_path), use_sudo)
    lgr.info('Manager container Stopped')


@operation
def clean_manager_containers_and_image(docker_path='docker', use_sudo=False, delete_data_container=True,
                                       delete_images=True, **kwargs):
    _run_command('{0} rm cfy'.format(docker_path), ignore_failures=True, use_sudo=use_sudo)
    if delete_data_container:
        _run_command('{0} rm data'.format(docker_path), ignore_failures=True, use_sudo=use_sudo)
    if delete_images:
        _run_command('{0} rmi cloudify:latest'.format(docker_path), ignore_failures=True, use_sudo=use_sudo)


def _handle_ssl_configuration(ssl_configuration):
    enabled = ssl_configuration.get(
        constants.SSL_ENABLED_PROPERTY_NAME, False)
    if enabled is True:
        # TODO: Must revisit this awesomeness at some stage
        # cert_path = ssl_configuration.get(
        #     constants.SSL_CERTIFICATE_PATH_PROPERTY_NAME)
        # if not cert_path:
        #     raise NonRecoverableError(
        #         'SSL is enabled => certificate path must be provided')
        # cert_path = os.path.expanduser(cert_path)
        # if not os.path.exists(cert_path):
        #     raise NonRecoverableError(
        #         'The certificate path [{0}] does not exist'
        #             .format(cert_path))
        # key_path = ssl_configuration.get(
        #     constants.SSL_PRIVATE_KEY_PROPERTY_NAME)
        # if not key_path:
        #     raise NonRecoverableError(
        #         'SSL is enabled => private key path must be provided')
        # key_path = os.path.expanduser(key_path)
        # if not os.path.exists(key_path):
        #     raise NonRecoverableError(
        #         'The private key path [{0}] does not exist'
        #             .format(key_path))
        # os.environ[constants.CLOUDIFY_SSL_CERT] = cert_path
        # rest_port = constants.SECURED_REST_PORT
        #
        # _copy_ssl_files(local_cert_path=cert_path,
        #                 remote_cert_path=HOST_SSL_CERTIFICATE_PATH,
        #                 local_key_path=key_path,
        #                 remote_key_path=HOST_SSL_PRIVATE_KEY_PATH)
        rest_port = constants.DEFAULT_REST_PORT
    else:
        rest_port = constants.DEFAULT_REST_PORT
    ctx.instance.runtime_properties[REST_PORT] = rest_port


@operation
def bootstrap_docker(cloudify_packages, manager_ip, cloudify_home=DEFAULT_CLOUDIFY_HOME_DIR,
                     docker_path=DEFAULT_DOCKER_PATH, elasticsearch_host=DEFAULT_ELASTICSEARCH_HOST,
                     elasticsearch_port=DEFAULT_ELASTICSEARCH_PORT, provider_context=None,
                     bootstrap_elasticsearch=True, **kwargs):
    from fabric_plugin.tasks import FabricTaskError

    global lgr
    lgr = ctx.logger

    lgr.info('initializing manager on local machine')

    def post_bootstrap_actions(wait_for_services_timeout=180):
        import sys

        port = 80
        lgr.info(
            'waiting for cloudify management services to start on port {0}'.format(port))
        started = _wait_for_management(
            manager_ip, wait_for_services_timeout, port)
        if not started:
            err = 'failed waiting for cloudify management services to start.'
            lgr.info(err)
            raise NonRecoverableError(err)

        if bootstrap_elasticsearch:
            try:
                _bootstrap_elasticsearch(elasticsearch_host, elasticsearch_port)
            except:
                lgr.error('Failed to bootstrap Elasticsearch Indexes')
                lgr.error(str(sys.exc_info()))
                raise
        else:
            lgr.info('Skipping Elasticsearch Bootstrap as not required by Blueprint')

        _set_manager_endpoint_data(manager_ip)
        try:
            _upload_provider_context('', os.path.expanduser(cloudify_home), provider_context)
        except:
            lgr.error(str(sys.exc_info()))

            if ctx.instance.runtime_properties.has_key('containers_started'):
                del ctx.instance.runtime_properties['containers_started']
            raise
        ctx.instance.runtime_properties['containers_started'] = 'True'
        return True

    _run_command('mkdir -p {0}'.format(cloudify_home))

    docker_exec_command = docker_path
    data_container_name = 'data'
    cfy_container_name = 'cfy'
    if _container_exists(docker_exec_command, data_container_name) or \
            _container_exists(docker_exec_command, cfy_container_name):
        err = 'a container instance with name {0}/{1} already exists.' \
            .format(data_container_name, cfy_container_name)
        raise NonRecoverableError(err)

    docker_image_url = cloudify_packages.get('docker', {}).get('docker_url')
    if not docker_image_url:
        raise NonRecoverableError('no docker URL found in packages')
    try:
        lgr.info('importing cloudify-manager docker image from {0}'
                 .format(docker_image_url))
        _run_command('{0} import {1} cloudify'
                     .format(docker_exec_command, docker_image_url))
    except FabricTaskError as e:
        err = 'failed importing Cloudify docker image from {0}. reason:{1}' \
            .format(docker_image_url, str(e))
        lgr.error(err)
        raise NonRecoverableError(err)

    cloudify_config = ctx.node.properties['cloudify']
    security_config = cloudify_config.get('security', {})
    security_config_file = _handle_security_configuration(security_config, os.path.expanduser(cloudify_home))

    ssl_configuration = security_config.get('ssl', {})
    _handle_ssl_configuration(ssl_configuration)

    lgr.info('exposing all ports from container, using HOST network}')
    cfy_management_options = ('-t '
                              '--volumes-from data '
                              '--net=host '
                              '-e MANAGEMENT_IP={0} '
                              '-e MANAGER_REST_SECURITY_CONFIG_PATH={1} '
                              '--restart=always '
                              '-d '
                              'cloudify '
                              '/sbin/my_init'
                              .format(manager_ip, os.path.normpath("/root/{0}".format(security_config_file))))

    agent_packages = cloudify_packages.get('agents')
    if agent_packages:
        # compose agent installation command.
        data_container_work_dir = '/tmp/work_dir'
        agents_dest_dir = '/opt/manager/resources/packages'
        agent_packages_install_cmd = \
            _get_install_agent_pkgs_cmd(agent_packages,
                                        data_container_work_dir,
                                        agents_dest_dir)
        agent_pkgs_mount_options = '-v {0} -w {1} ' \
            .format(agents_dest_dir,
                    data_container_work_dir)
    else:
        lgr.info('no agent packages were provided')
        agent_packages_install_cmd = 'echo no agent packages provided'
        agent_pkgs_mount_options = ''

    # command to copy host VM home dir files into the data container's home.
    backup_vm_files_cmd, home_dir_mount_path = _get_backup_files_cmd('cloudify')

    install_plugins_cmd = _handle_plugins_and_create_install_cmd(
        cloudify_config.get('plugins', {}))

    data_container_start_cmd = '{0} && {1} && {2} && echo Data-only container' \
        .format(agent_packages_install_cmd,
                backup_vm_files_cmd,
                install_plugins_cmd)
    data_container_options = ('-t '
                              '{0} '
                              '-v ~/:{1} '
                              '-v /root '
                              '-v /etc/init.d '
                              '-v /etc/default '
                              '-v /opt/manager/resources '
                              '-v /opt/manager/env '
                              '-v /etc/service/riemann '
                              '-v /etc/service/elasticsearch/data '
                              '-v /etc/service/elasticsearch/logs '
                              '-v /opt/influxdb/shared/data '
                              '-v /var/log/cloudify '
                              'cloudify sh -c \'{2}\''
                              .format(agent_pkgs_mount_options,
                                      home_dir_mount_path,
                                      data_container_start_cmd))

    try:
        lgr.info('starting a new cloudify data container')
        _run_docker_container(docker_exec_command, data_container_options,
                              data_container_name)
        lgr.info('starting a new cloudify mgmt docker services container')
        _run_docker_container(docker_exec_command, cfy_management_options,
                              cfy_container_name, attempts_on_corrupt=5)
    except FabricTaskError as e:
        err = 'failed running cloudify docker container. ' \
              'error is {0}'.format(str(e))
        lgr.error(err)
        raise NonRecoverableError(err)

    return post_bootstrap_actions()


def _get_backup_files_cmd(cloudify_home):
    container_tmp_homedir_path = '/tmp/home'
    backup_homedir_cmd = 'cp -rf {0}/{1}/. /root' \
        .format(container_tmp_homedir_path, cloudify_home)
    return backup_homedir_cmd, container_tmp_homedir_path


def _get_install_agent_pkgs_cmd(agent_packages,
                                agents_pkg_path,
                                agents_dest_dir):
    download_agents_cmd = ''
    install_agents_cmd = ''
    for agent_name, agent_url in agent_packages.items():
        download_agents_cmd += 'curl -O {0}{1} ' \
            .format(agent_url, ' && ')

    install_agents_cmd += 'rm -rf {0}/* && dpkg -i {1}/*.deb' \
        .format(agents_dest_dir,
                agents_pkg_path)

    return '{0} {1}'.format(download_agents_cmd, install_agents_cmd)


def _handle_plugins_and_create_install_cmd(plugins):
    # no plugins configured, run a stub 'true' command
    if not plugins:
        return 'true'

    cloudify_plugins = 'cloudify/plugins'
    install_plugins = 'install_plugins.sh'

    # create location to place tar-gzipped plugins in
    _run_command('mkdir -p ~/{0}'.format(cloudify_plugins))

    # for each plugin tha is included in the blueprint, tar-gzip it
    # and place it in the plugins dir on the host
    for name, plugin in plugins.items():
        source = plugin['source']
        if source.split('://')[0] in ['http', 'https']:
            continue

        # temporary workaround to resolve absolute file path
        # to installed plugin using internal local workflows storage
        # information
        plugin_path = os.path.join(ctx._endpoint.storage.resources_root,
                                   source)

        with tempfile.TemporaryFile() as fileobj:
            with tarfile.open(fileobj=fileobj, mode='w:gz') as tar:
                tar.add(plugin_path, arcname=name)
            fileobj.seek(0)
            tar_remote_path = '{0}/{1}.tar.gz'.format(cloudify_plugins, name)
            fabric.api.put(fileobj, '~/{0}'.format(tar_remote_path))
            plugin['source'] = 'file:///root/{0}'.format(tar_remote_path)

    script_template = pkgutil.get_data('cloudify_cli.bootstrap.resources',
                                       'install_plugins.sh.template')
    script = jinja2.Template(script_template).render(plugins=plugins)
    fabric.api.put(StringIO(script), '~/{0}'.format(install_plugins))
    _run_command('chmod +x ~/{0}'.format(install_plugins))

    return '/root/{0}'.format(install_plugins)


def _wait_for_management(ip, timeout, port=constants.DEFAULT_REST_PORT):
    protocol = 'http' if port == constants.DEFAULT_REST_PORT else 'https'
    validation_url = '{0}://{1}:{2}/version'.format(protocol, ip, port)
    lgr.info('waiting for url {0} to become available'.format(validation_url))

    end = time() + timeout

    while end - time() >= 0:
        try:
            status = urllib.urlopen(validation_url).getcode()
            if status == 200:
                return True

        except IOError as e:
            lgr.debug('error waiting for {0}. reason: {1}'
                      .format(validation_url, e.message))
        sleep(5)

    return False


def _set_manager_endpoint_data(manager_ip, manager_user='root'):
    ctx.instance.runtime_properties[MANAGER_IP_RUNTIME_PROPERTY] = manager_ip
    ctx.instance.runtime_properties[MANAGER_USER_RUNTIME_PROPERTY] = manager_user
    ctx.instance.runtime_properties[MANAGER_KEY_PATH_RUNTIME_PROPERTY] = 'id_rsa'


def _handle_security_configuration(blueprint_security_config, cloudify_home):
    security_config_file = 'rest-security-config.json'

    security_config_path = os.path.normpath('{0}/{1}'.format(cloudify_home, security_config_file))

    secured_server = blueprint_security_config.get(
        'enabled', DEFAULT_SECURITY_MODE)
    auth_token_generator = blueprint_security_config.get(
        'auth_token_generator', {})
    securest_userstore_driver = blueprint_security_config.get(
        'userstore_driver', {})
    securest_authentication_providers = blueprint_security_config.get(
        'authentication_providers', [])
    securest_log_level = blueprint_security_config.get(
        'audit_log_level', DEFAULT_SECURITY_LOG_LEVEL)
    securest_log_file = blueprint_security_config.get(
        'audit_log_file', DEFAULT_SECURITY_LOG_FILE)
    securest_log_file_size_MB = blueprint_security_config.get(
        'audit_log_file_size_MB', DEFAULT_SECURITY_LOG_FILE_SIZE_MB)
    securest_log_files_backup_count = blueprint_security_config.get(
        'audit_log_files_backup_count',
        DEFAULT_SECURITY_LOG_FILES_BACKUP_COUNT)

    security_config = dict(
        secured_server=secured_server,
        auth_token_generator=auth_token_generator,
        securest_userstore_driver=securest_userstore_driver,
        securest_authentication_providers=securest_authentication_providers,
        securest_log_level=securest_log_level,
        securest_log_file=securest_log_file,
        securest_log_file_size_MB=securest_log_file_size_MB,
        securest_log_files_backup_count=securest_log_files_backup_count
    )
    if os.path.exists(security_config_path):
        os.remove(security_config_path)

    security_config_file_obj = open(security_config_path, 'w')
    json.dump(security_config, security_config_file_obj)
    return security_config_file


def _copy_ssl_files(
        local_cert_path, remote_cert_path, local_key_path, remote_key_path):
    ctx.logger.info(
        'Copying SSL certificate to management machine: {0} -> {1}'.format(
            local_cert_path, remote_cert_path))
    fabric.api.put(local_cert_path, remote_cert_path)

    ctx.logger.info(
        'Copying SSL key to management machine: {0} -> {1}'.format(
            local_key_path, remote_key_path))
    fabric.api.put(local_key_path, remote_key_path)


def _copy_agent_key(agent_local_key_path, agent_remote_key_path):
    if not agent_local_key_path:
        return
    agent_local_key_path = os.path.expanduser(agent_local_key_path)
    ctx.logger.info(
        'Copying agent key to management machine: {0} -> {1}'.format(
            agent_local_key_path, agent_remote_key_path))
    fabric.api.put(agent_local_key_path, agent_remote_key_path)


def _upload_provider_context(remote_agents_private_key_path, cloudify_home,
                             provider_context=None):
    ctx.logger.info('updating provider context on management server...')
    provider_context = provider_context or dict()
    cloudify_configuration = ctx.node.properties['cloudify']
    cloudify_configuration['cloudify_agent']['agent_key_path'] = \
        remote_agents_private_key_path
    provider_context['cloudify'] = cloudify_configuration
    ctx.instance.runtime_properties[PROVIDER_RUNTIME_PROPERTY] = \
        provider_context

    cloudify_configuration['manager_deployment'] = _dump_manager_deployment()

    context_file = 'provider-context.json'
    context_path = os.path.normpath("{0}/{1}".format(cloudify_home, context_file))
    if os.path.exists(context_path):
        os.remove(context_path)
    provider_context_json_file = open(context_path, "w")
    full_provider_context = {
        'name': 'provider',
        'context': provider_context
    }
    json.dump(full_provider_context, provider_context_json_file)
    provider_context_json_file.close()

    upload_provider_context_cmd = 'curl --fail -v -XPOST http://localhost:8101/provider/context -H ' \
                                  '"Content-Type: application/json" -d @{0}'.format(context_path)

    _run_command(upload_provider_context_cmd)


def _bootstrap_elasticsearch(elasticsearch_host='localhost', port=9200):
    lgr.info("Removing old Cloudify Indexes and bootstrapping new once")
    es = 'http://{0}:{1}'.format(elasticsearch_host, port)

    delete_events_indexe = 'curl --retry 5 --retry-delay 3 -XDELETE {0}/cloudify_events/'.format(es)
    delete_storage_index = 'curl --retry 5 --retry-delay 3 -XDELETE {0}/cloudify_storage'.format(es)

    _run_command(delete_events_indexe, ignore_failures=True)
    _run_command(delete_storage_index, ignore_failures=True)

    create_events_index = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_events -d \'{{"settings": ' \
                          '{{"analysis":{{"analyzer":{{"default":{{"tokenizer": "whitespace"}}}}}}}}}}\''.format(es)
    _run_command(create_events_index)

    create_storage_index = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage -d \'{{"settings": ' \
                           '{{"analysis":{{"analyzer":{{"default":{{"tokenizer": "whitespace"}}}}}}}}}}\''.format(es)
    _run_command(create_storage_index)

    create_blueprint_mapping = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage/blueprint/_mapping -d' \
                               ' \'{{"blueprint":{{"properties":{{"plan":{{"enabled": false}}}}}}}}\''.format(es)
    _run_command(create_blueprint_mapping)

    create_deployment_mapping = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage/deployment/_mapping -d ' \
                                '\'{{"deployment":{{"properties":{{"workflows":{{"enabled": false}}, "inputs": ' \
                                '{{"enabled": false}},"policy_type":{{"enabled": false}}, "policy_triggers": ' \
                                '{{"enabled": false}}, "groups":{{"enabled": false}},"outputs":{{"enabled": ' \
                                'false}}}}}}}}\''.format(es)
    _run_command(create_deployment_mapping)

    create_node_mapping = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage/node/_mapping -d \'{{"node": ' \
                          '{{"_id":{{"path": "id"}}, "properties":{{"types":{{"type": "string", "index_name": "type"' \
                          '}}, "properties":{{"enabled": false}},"operations":{{"enabled": false }},"relationships":' \
                          '{{"enabled": false }}}}}}}}\''.format(es)
    _run_command(create_node_mapping)

    create_node_instance = 'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage/node_instance/_mapping -d ' \
                           '\'{{"node_instance": {{"_id": {{"path": "id"}}, "properties":{{"runtime_properties":{{' \
                           '"enabled": false}}}}}}}}\''.format(es)
    _run_command(create_node_instance)
    create_deployment_modification = \
        'curl --retry 5 --retry-delay 3 -XPUT {0}/cloudify_storage/deployment_modification/_mapping -d ' \
        '\'{{"deployment_modification":{{"_id":{{"path": "id"}}, "properties":{{"modified_nodes": ' \
        '{{"enabled": false}}, "node_instances":{{"enabled": false}}, "context":{{"enabled": false}}}}}}}}\''.format(es)
    _run_command(create_deployment_modification)


def _run_command(command, use_sudo=False, as_user=None, capture=False, ignore_failures=False):
    the_command = command
    if use_sudo:
        if as_user:
            the_command = "sudo -u {0} {1}".format(as_user, command)
        else:
            the_command = "sudo {0}".format(command)
    lgr.info(">> command: [{0}]".format(the_command))
    try:
        return run_local(the_command, capture=capture)
    except:
        if ignore_failures:
            return True
        raise


def _run_command_in_cfy(command, docker_path=None, use_sudo=True,
                        terminal=False):
    if not docker_path:
        docker_path = 'docker'
    exec_command = 'exec -t' if terminal else 'exec'
    full_command = '{0} {1} cfy {2}'.format(
        docker_path, exec_command, command)
    if use_sudo:
        full_command = 'sudo {0}'.format(full_command)
    _run_command(full_command)


def _container_exists(docker_exec_command, container_name):
    from exceptions import SystemExit

    try:
        inspect_command = '{0} inspect {1}'.format(docker_exec_command,
                                                   container_name)
        _run_command(inspect_command)
        return True
    except SystemExit:
        return False


def _run_docker_container(docker_exec_command, container_options,
                          container_name, attempts_on_corrupt=1):
    run_cmd = '{0} run --name {1} {2}' \
        .format(docker_exec_command, container_name, container_options)
    for i in range(0, attempts_on_corrupt):
        try:
            lgr.debug('starting docker container {0}'.format(container_name))
            return _run_command(run_cmd)
        except:
            lgr.debug('container execution failed on attempt {0}/{1}'
                      .format(i + 1, attempts_on_corrupt))
            container_exists = _container_exists(docker_exec_command,
                                                 container_name)
            if container_exists:
                lgr.debug('container {0} started in a corrupt state. '
                          'removing container.'.format(container_name))
                rm_container_cmd = '{0} rm -f {1}'.format(docker_exec_command,
                                                          container_name)
                _run_command(rm_container_cmd)
            if not container_exists or i + 1 == attempts_on_corrupt:
                lgr.error('failed executing command: {0}'.format(run_cmd))
                raise
            sleep(2)


def get_machine_distro():
    return _run_command('python -c "import platform, json, sys; '
                        'sys.stdout.write(\'{0}\\n\''
                        '.format(json.dumps(platform.dist())))"')


def _validate_package_url_accessible(package_url):
    ctx.logger.debug('checking whether url {0} is accessible'.format(
        package_url))
    status = urllib.urlopen(package_url).getcode()
    if not status == 200:
        err = ('url {0} is not accessible'.format(package_url))
        ctx.logger.error('VALIDATION ERROR: ' + err)
        raise NonRecoverableError(err)
    ctx.logger.debug('OK: url {0} is accessible'.format(package_url))


# temp workaround to enable teardown and recovery from different machines
def _dump_manager_deployment():
    from cloudify_cli.bootstrap.bootstrap import dump_manager_deployment
    from cloudify_cli.bootstrap.bootstrap import load_env

    # explicitly write the manager node instance id to local storage
    env = load_env('manager')
    with env.storage.payload() as payload:
        payload['manager_node_instance_id'] = ctx.instance.id

    # explicitly flush runtime properties to local storage
    ctx.instance.update()
    return dump_manager_deployment()
