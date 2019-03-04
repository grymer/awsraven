# awsraven

The Python script 'function.py' is an AWS Lambda function. It is a serverless implementation of the WLS side of the WAA->WLS communication protocol used by the University of Cambridge's central web authentication service.

In its current state (version "1.0.0") it is not considered to be fit for production use. Although fully functional, it is intended as a "proof of concept", a test bed of ideas. The code is largely untested, and there may still be bugs.

If you're interested in implementing a WLS in the cloud, or just curious about developing AWS Lambda functions, then this project might be of interest to you.

This function uses the Python 3.7 runtime, and requires both Crypto and bcrypt modules to work. These additional modules need to be packaged separately. To build a deployable package:

1. Create a package directory: "mkdir package".
2. Install requisite modules under the new package directory: "pip install bcrypt pycrypto --target .".
3. Create a Zip archive: "zip -r9 ../function.zip .".
4. Return to parent directory: "cd ..".
5. Add function to Zip archive: "zip -g function.zip function.py"

The Zip archive can be uploaded to the AWS Lambda Management Console.

The function is designed to work with AWS API Gateway. You will need to create resources for GET and POST methods, and use Lambda Proxy integration.

The file 'pubkey1' has been exported from the embedded private key, and is in the correct format to be used with Apache/mod_ucam_webauth for testing.
