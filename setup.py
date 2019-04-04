from setuptools import setup, find_packages

setup(name='cryptopals_roald_solutions',
      version='0.1',
      description='Solution to the challenges on https://cryptopals.com',
      author='Roald Storm',
      author_email='roaldstorm@gmail.com',
      license='GPL-3',
      packages=find_packages(where="src"),
      package_dir={"": "src"},
      tests_require = ["pytest"],
      zip_safe=False)