Keypot (key-depot, or a play on words where you keep a key under a pot) is a simple python routine that will allow you to use the Amazon KMS service in conjunction with AWS DynamoDB to store and retrieve variables in encrypted form in a database that is easy to query and never has to store a key on disk or inside a container.

# Prerequisites:
- Set up your Amazon environnment to already be ready for AWS API calls (e.g. add .aws directory or execute aws configure from CLI)
- Set up an AWS Dynamo DB table with a hash key:  env-variable-name (type is String)
- Ensure your account or instance has the proper IAM roles (full definition coming soon!)

#Design Goals:
- Be able to run this either as a standalone script or as an AWS Lambda function
- Tertiary goal, but making it run both in Python 2 and 3.  Testing in 2.7.6 and 3.4.3

#Usage:
##General:
    usage: keypot.py [-h] [-v] {encrypt,decrypt,list,delete} ...
    
    Keypot - Encrypts, Decrypts, and Manages Secrets stored in AWS DynamoDB with
    KMS key
    
    positional arguments:
      {encrypt,decrypt,list,delete}
                            For more information and usage information, get help
                            by using the {name} -h syntax
        encrypt             Keypot Encrypt - Encrypts value in DynamoDB using KMS
        decrypt             Keypot Decrypt - Decrypt value in DynamoDB using KMS
        list                Keypot List - List all keys available in DynamoDB -
                            NOT YET IMPLEMENTED
        delete              Keypot Delete - Removes a key from DynamoDB - NOT YET
                            IMPLEMENTED
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         show program's version number and exit

##Encrypt:
    usage: keypot.py encrypt [-h] [-f PARAMETER_FILE] -k KMS_KEY -p PARAMETER_KEY
                             [-r REGION] -t DDB_TABLE [-o] [-v PARAMETER_VALUE]
    
    optional arguments:
      -h, --help            show this help message and exit
      -f PARAMETER_FILE, --parameter_file PARAMETER_FILE
                            Location of file you want to upload (e.g. SSL private
                            key). One of this or parameter_value required.
      -k KMS_KEY, --kms_key KMS_KEY
                            Name of AWS KMS Customer Master Key (ex: alias/test-
                            key)
      -p PARAMETER_KEY, --parameter_key PARAMETER_KEY
                            Name of Parameter to put into DynamoDB
      -r REGION, --region REGION
                            Name of AWS Region to use for both KMS and DynamoDB
      -t DDB_TABLE, --ddb_table DDB_TABLE
                            Name of existing DynamoDB Table to use in look-up
      -o, --overwrite       Force overwrite of existing value in DynamoDB without
                            prompting for overwrite
      -v PARAMETER_VALUE, --parameter_value PARAMETER_VALUE
                            Value of Parameter to put into DynamoDB. One of this
                            or parameter_file required.

##Decrypt:
    usage: keypot.py decrypt [-h] -k KMS_KEY -p PARAMETER_KEY [-r REGION] -t
                             DDB_TABLE
    
    optional arguments:
      -h, --help            show this help message and exit
      -k KMS_KEY, --kms_key KMS_KEY
                            Name of AWS KMS Customer Master Key (ex: alias/test-
                            key)
      -p PARAMETER_KEY, --parameter_key PARAMETER_KEY
                            Name of Parameter to put into DynamoDB
      -r REGION, --region REGION
                            Name of AWS Region to use for both KMS and DynamoDB
      -t DDB_TABLE, --ddb_table DDB_TABLE
                            Name of existing DynamoDB Table to use in look-up

##List:
    usage: keypot.py list [-h] [-r REGION] -t DDB_TABLE
    
    optional arguments:
      -h, --help            show this help message and exit
      -r REGION, --region REGION
                            Name of AWS Region to use for both KMS and DynamoDB
      -t DDB_TABLE, --ddb_table DDB_TABLE
                            Name of existing DynamoDB Table to use in look-up

##Delete:
    usage: keypot.py delete [-h] -p PARAMETER_KEY [-r REGION] -t DDB_TABLE
    
    optional arguments:
      -h, --help            show this help message and exit
      -p PARAMETER_KEY, --parameter_key PARAMETER_KEY
                            Name of Parameter to put into DynamoDB
      -r REGION, --region REGION
                            Name of AWS Region to use for both KMS and DynamoDB
      -t DDB_TABLE, --ddb_table DDB_TABLE
                            Name of existing DynamoDB Table to use in look-up

# Future Enhancements:
- Add support to upload a file from S3 for encryption (useful for Lambda?)