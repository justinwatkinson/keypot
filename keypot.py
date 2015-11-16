#!/usr/bin/python3
import boto3
import datetime
from Crypto import Random
from Crypto.Cipher import AES
import argparse
import base64
from argparse import Namespace

#VERSION
keypot_version='Keypot-0.2'
ddb_hash_key_name='env-variable-name'

#Pads the data to suit the AES-256 encryption requirements
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(str(s[-1]))]

#Global boto3 clients
kms = None
ddb = None

#global variables - since this isn't run as a web server, thread safety shouldn't be a big deal.
boto_master_key_id = None
ddb_table_name = None
parameter_key = None
parameter_value = None
parameter_file = None

#Used to encrypt locally on this machine using the key generated from KMS
def local_encrypt(message, key, key_size=256):
    message = pad(str(message))
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB, iv)
    return iv + cipher.encrypt(message)

#Used to decrypt locally on this machine using the key decrypted from KMS
def local_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(plaintext.decode('ASCII'))

def create_ddb_client(args):
    global ddb
    
    if 'region' in args:
        if args['region'] != '':
            ddb = boto3.client('dynamodb', region_name=args['region'])
            return
    
    ddb = boto3.client('dynamodb')
    return
    
def create_kms_client(args):
    global kms
    
    if 'region' in args:
        if args['region'] != '':
            kms = boto3.client('kms', region_name=args['region'])
            return
    
    kms = boto3.client('kms')
    return
    

def encrypt_and_store():
    global ddb
    global kms
    #Generate a key using KMS service
    data_key = kms.generate_data_key(KeyId=boto_master_key_id,KeySpec='AES_256') #I use the boto key's id
    encrypted_data_key = data_key['CiphertextBlob']
    plaintext_data_key = data_key['Plaintext']
    
    #encrypt data locally and write it to Dynamo
    encrypted_data = local_encrypt(parameter_value,plaintext_data_key)
    
    ddb.put_item(
        TableName=ddb_table_name,
        Item={
            'env-variable-name': {
                'S': parameter_key
            },
            'env-variable-enc-value': {
                'B': encrypted_data
            },
            'env-variable-enc-kms-key': {
                'B': encrypted_data_key
            }
        }
    )
    
    return

def read_value_from_file():
    with open(parameter_file, 'r') as f:
        read_value=f.read()
    f.closed
    return read_value

#Used to decrypt the data key pulled from DynamoDB using KMS
def decrypt_kms_data(encrypted_data):
    global kms
    decrypted = kms.decrypt(CiphertextBlob=encrypted_data)
    return decrypted

#Pull data dictionary from DynamoDB
def read_from_ddb():
    response = ddb.get_item(
        TableName=ddb_table_name,
        Key={
            'env-variable-name': {
                'S': parameter_key
            }
        }
    )
    return response

#Pull data dictionary from DynamoDB
def list_from_ddb():
    response = ddb.scan(TableName=ddb_table_name,ProjectionExpression="#E",ExpressionAttributeNames={"#E": ddb_hash_key_name})
    if response['Count'] > 0:
        return response['Items']
    
    #empty table
    print('Table was empty - nothing to list!')
    return 

def delete_from_ddb():
    #Key should always be a 'S' (String) type
    response = ddb.delete_item(
        TableName=ddb_table_name,
        Key={
            'env-variable-name': {
                'S': parameter_key
            }
        }
    )
    return response

def do_encrypt(encrypt_args):
    #use global variable references - makes the function hand-offs a bit easier
    global kms
    global ddb
    global boto_master_key_id
    global ddb_table_name
    global parameter_key
    global parameter_value
    global parameter_file
    
    #set global vars
    create_kms_client(encrypt_args)
    create_ddb_client(encrypt_args)
    
    boto_master_key_id = encrypt_args['kms_key']
    ddb_table_name = encrypt_args['ddb_table']
    parameter_key = encrypt_args['parameter_key']
    
    if 'parameter_value' in encrypt_args:
        if (encrypt_args['parameter_value']):
            parameter_value = encrypt_args['parameter_value']
        
    if ('parameter_file' in encrypt_args):
        if (encrypt_args['parameter_file']):
            parameter_file = encrypt_args['parameter_file']
    
    #set local vars
    overwrite_flag=False #set default value to false, force it to be 
    if 'overwrite' in encrypt_args:
        if (encrypt_args['overwrite']):
            overwrite_flag = True
    
    #check if parameter already exists (only if overwrite is true, otherwise just blindly overwrite)
    if overwrite_flag == False:
        ddb_pull = {}
        ddb_pull = read_from_ddb()
        if 'Item' in ddb_pull:
            output_overwrite='Variable already exists in DynamoDB - please use the overwrite flag to add this to database.'
            print(output_overwrite)
            return(output_overwrite)
    
    #reads the file from disk specified in args
    if parameter_file:
        parameter_value=read_value_from_file()
        
    #perform encrypt/DDB operations
    encrypt_and_store()
    
    output_status='Parameter ' + parameter_key + ' uploaded successfully'
    print(output_status)
    return(output_status)
    
def do_decrypt(decrypt_args):
    #use global variable references - makes the function hand-offs a bit easier
    global kms
    global ddb
    global boto_master_key_id
    global ddb_table_name
    global parameter_key
    
    #TODO:  Validate arguments for kms_key
    
    #set global vars
    create_kms_client(decrypt_args)
    create_ddb_client(decrypt_args)
    
    boto_master_key_id = decrypt_args['kms_key']
    ddb_table_name = decrypt_args['ddb_table']
    parameter_key = decrypt_args['parameter_key']
    
    #Read and decrypt
    returned_variable_dict = read_from_ddb()
    returned_db_value = returned_variable_dict['Item']['env-variable-enc-value']['B']
    returned_db_kms_encrypted_key = returned_variable_dict['Item']['env-variable-enc-kms-key']['B']
    kms_decrypted_key = decrypt_kms_data(returned_db_kms_encrypted_key)['Plaintext']
    final_value = local_decrypt(returned_db_value, kms_decrypted_key)
    
    #Print as plain text - test and will work both with regular strings and binaries from command-line
    #TODO:  See if we can somehow alter the AWS Lambda do use this format instead of adding back control chars like \n to response
    print(final_value)
    return(final_value)

def do_delete(delete_args):
    global ddb
    global ddb_table_name
    global parameter_key
    
    create_ddb_client(delete_args)
    
    ddb_table_name=delete_args['ddb_table']
    parameter_key = delete_args['parameter_key']
    
    #Removes from DynamoDB based on DDB key
    delete_result = delete_from_ddb()
    if 'ResponseMetadata' in delete_result:
        if delete_result['ResponseMetadata']['HTTPStatusCode'] == 200:
            result='Successfully removed ' + str(parameter_key) + ' from ' + ddb_table_name
            print(result)
            return(result)
        else:
            result='A problem occurred - unable to remove ' + str(parameter_key) + ' from ' + ddb_table_name
            print(result)
            return(result)
    
    return

def do_list(list_args):
    #TODO:  Maybe add different format options (e.g. yaml, json)
    global ddb
    global ddb_table_name
    global parameter_key
    
    create_ddb_client(list_args)
    
    ddb_table_name=list_args['ddb_table']
    
    #get list of "String" key attributes from DynamoDB
    variable_list = list_from_ddb()
    if variable_list:
        for var in variable_list:
            print(var[ddb_hash_key_name]['S'])
        
    return variable_list

#default entry point - possible future enhancement would be to turn this into a lambda function
def keypot_cli():
    parser = {}
    action='super'
    parser[action] = argparse.ArgumentParser(description='Keypot - Encrypts, Decrypts, and Manages Secrets stored in AWS DynamoDB with KMS key')
    parser[action].add_argument('-v','--version', action='version', version=(keypot_version))
    subparser = parser['super'].add_subparsers(help='For more information and usage information, get help by using the {name} -h syntax')
    
    #encrypt
    action='encrypt'
    parser[action] = subparser.add_parser(action, help='Keypot Encrypt - Encrypts value in DynamoDB using KMS')
    #does not support both value and an input file, so using a mutually exclusive group
    encrypt_mutual_exclusive = parser[action].add_mutually_exclusive_group()
    encrypt_mutual_exclusive.add_argument('-f','--parameter_file', help='Location of file you want to upload (e.g. SSL private key).  One of this or parameter_value required.',required=False)
    parser[action].add_argument('-k','--kms_key', help='Name of AWS KMS Customer Master Key (ex: alias/test-key)',required=True)
    parser[action].add_argument('-p','--parameter_key', help='Name of Parameter to put into DynamoDB',required=True)
    parser[action].add_argument('-r','--region', help='Name of AWS Region to use for both KMS and DynamoDB',required=False)
    parser[action].add_argument('-t','--ddb_table', help='Name of existing DynamoDB Table to use in look-up',required=True)
    parser[action].add_argument('-o','--overwrite', action='store_true', help='Force overwrite of existing value in DynamoDB without prompting for overwrite',required=False,default=False)
    encrypt_mutual_exclusive.add_argument('-v','--parameter_value', help='Value of Parameter to put into DynamoDB.    One of this or parameter_file required.',required=False)
    parser[action].set_defaults(action=action)

    #decrypt
    action='decrypt'
    parser[action] = subparser.add_parser(action, help='Keypot Decrypt - Decrypt value in DynamoDB using KMS')
    parser[action].add_argument('-k','--kms_key', help='Name of AWS KMS Customer Master Key (ex: alias/test-key)',required=True)
    parser[action].add_argument('-p','--parameter_key', help='Name of Parameter to put into DynamoDB',required=True)
    parser[action].add_argument('-r','--region', help='Name of AWS Region to use for both KMS and DynamoDB',required=False)
    parser[action].add_argument('-t','--ddb_table', help='Name of existing DynamoDB Table to use in look-up',required=True)
    parser[action].set_defaults(action=action)
    
    #list
    action='list'
    parser[action] = subparser.add_parser(action, help='Keypot List - List all keys available in DynamoDB - NOT YET IMPLEMENTED')
    parser[action].add_argument('-r','--region', help='Name of AWS Region to use for both KMS and DynamoDB',required=False)
    parser[action].add_argument('-t','--ddb_table', help='Name of existing DynamoDB Table to use in look-up',required=True)
    parser[action].set_defaults(action=action)
    
    #delete
    action='delete'
    parser[action] = subparser.add_parser(action, help='Keypot Delete - Removes a key from DynamoDB - NOT YET IMPLEMENTED')
    parser[action].add_argument('-p','--parameter_key', help='Name of Parameter to put into DynamoDB',required=True)
    parser[action].add_argument('-r','--region', help='Name of AWS Region to use for both KMS and DynamoDB',required=False)
    parser[action].add_argument('-t','--ddb_table', help='Name of existing DynamoDB Table to use in look-up',required=True)
    parser[action].set_defaults(action=action)
    
    #based on sub-argument, send to correct function
    #change Namespace args back to dictionary so that we get consistent behavior between Lambda and CLI versions
    super_args = parser['super'].parse_args()
    if "action" in vars(super_args):
        if super_args.action == 'encrypt':
            do_encrypt(encrypt_args=vars(super_args))
        if super_args.action == 'decrypt':
            do_decrypt(decrypt_args=vars(super_args))
        if super_args.action == 'list':
            do_list(list_args=vars(super_args))
        if super_args.action == 'delete':
            do_delete(delete_args=vars(super_args))
    
    return

#entry point for the lambda function
#This function is to massage input to match the rest of the CLI function, and customize any output for Lambda consumption
def keypot_lambda_handler(event, context):
    #TODO:  do some basic checking (e.g., is there an action and options in the dictionary?)
    
    #ENCRYPT
    if event['action'] == 'encrypt':
        #Put note about using file method - will implement an "upload from S3" option
        if ('file' in event['options']):
            return('File upload is not  supported by Lambda invocation.  Please use upload from S3')
        output_string=do_encrypt(event['options'])
        return(output_string)
    
    #DECRYPT
    if event['action'] == 'decrypt':
        output_string=do_decrypt(event['options'])
        return output_string
    
    #LIST
    if event['action'] == 'list':
        variable_list=do_list(event['options'])
        output_string=''
        if variable_list:
            for var in variable_list:
                output_string+=var[ddb_hash_key_name]['S']
                output_string+='\n'
        return output_string
    
    #DELETE
    if event['action'] == 'delete':
        output_string=do_delete(event['options'])
        return output_string
    
#primary method when executed directly
if __name__ == '__main__':
    keypot_cli()