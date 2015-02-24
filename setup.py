# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import setuptools


setuptools.setup(
    name='keyless_fernet',
    version='1.0.0',
    description='Parse Fernet tokens as much as possible without using a key.',
    author='Dolph Mathews',
    author_email='dolph.mathews@gmail.com',
    url='http://github.com/dolph/keyless-fernet',
    install_requires=[],
    packages=setuptools.find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
    ],
)
