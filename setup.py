try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

files = ["config/*"]

setup(name = "dyndd",
    version = "0.1",
    description = "Dynamic DNS Daemon",
    author = "_nalle",
    author_email = "rickard.eriksson@gigabit.nu",
    url = "https://www.dyndd.xyz",
    packages = ['dyndd'],
    package_data = {'dyndd' : files, 'dyndd/ipaddr': files, 'dyndd/controller': files},
    long_description = """DNS Daemon that takes records from a mysql database and returns them on request""",
    install_requires = ['psutil','setproctitle','twisted','MySQL-python']
)



#    scripts = ["bin/dyndd"],
#    data_files = [('/etc/dyndd', ['config/dyndd.conf']), ('/etc/init.d',['startupscripts/dyndd']),('/etc/logrotate.d',['logrotate.d/dyndd'])],
