#!/usr/bin/python

import unittest
import boto3
import keypot

#Module Variables (Global)
test_ddb_table='test-creds'
test_kms_key='alias/test-key'
test_ddb_name_text_var='unit-lambdatest-var'
test_ddb_name_text_val1='unit-lambdatest-value1'
test_ddb_name_text_val2='unit-lambdatest-value2'

class KeypotLambdaTestCase(unittest.TestCase):    
    
    @classmethod
    def setUpClass(self):
        print('\nBeginning Lambda test suite setup\n')
        #create a private key to test uploads
        self.remove_all_ddb_entries()
    
    @classmethod
    def tearDownClass(self):
        print('\nBeginning Lambda test suite tear down\n')
        #remove the private key created in setUp
        self.remove_all_ddb_entries()
        
    @classmethod
    def remove_all_ddb_entries(self):
        #Cleans up any potential failed runs before exiting
        print('Removing:' + str(test_ddb_name_text_var) + ' from ' + test_ddb_table )
        payload=b'{"action":"delete","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '"}}'
        lambda_client=boto3.client('lambda')
        lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
    
    def test_encrypt_value_no_override_empty(self):
        payload=b'{"action":"encrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","parameter_value":"' + test_ddb_name_text_val1 + '","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        #ends with uploaded successfully"
        self.assertRegexpMatches(result['Payload'].read(),'.*uploaded successfully\"$')
        
    def test_encrypt_value_no_override_override_failure(self):
        payload=b'{"action":"encrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","parameter_value":"' + test_ddb_name_text_val1 + '","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        check_value=result['Payload'].read() #Not sure why, but the assert doesn't like the result['Payload].read() expression, returns none when used in that context, even though it's a string
        #see if it returned the error from keypot
        self.assertRegexpMatches(check_value,str('.*'+ keypot.string_key_already_exists + '.*'))
        
    def test_encrypt_value_override_false_override_failure(self):
        payload=b'{"action":"encrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","parameter_value":"' + test_ddb_name_text_val1 + '","overwrite":"false","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        check_value=result['Payload'].read() #Not sure why, but the assert doesn't like the result['Payload].read() expression, returns none when used in that context, even though it's a string
        #see if it returned the error from keypot
        self.assertRegexpMatches(check_value,str('.*'+ keypot.string_key_already_exists + '.*'))
    
    def test_encrypt_value_with_overwrite(self):
        payload=b'{"action":"encrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","parameter_value":"' + test_ddb_name_text_val2 + '","overwrite":"true","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        #ends with uploaded successfully"
        self.assertRegexpMatches(result['Payload'].read(),'.*uploaded successfully\"$')
        
    def test_read_text_value1(self):
        payload=b'{"action":"decrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        #check to make sure value 1 was returned
        self.assertEqual(result['Payload'].read(),'\"'+test_ddb_name_text_val1+'\"')
        
    def test_read_text_value2(self):
        payload=b'{"action":"decrypt","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '","kms_key":"' + test_kms_key+'"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        #check to make sure value 2 was returned
        self.assertEqual(result['Payload'].read(),'\"'+test_ddb_name_text_val2+'\"')
    
    def test_list_function(self):
        payload=b'{"action":"list","options":{"ddb_table":"' + test_ddb_table + '"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        check_value=result['Payload'].read()
        self.assertRegexpMatches(check_value,str('.*'+ test_ddb_name_text_var + '.*'))
        
    def test_delete_text_key(self):
        payload=b'{"action":"delete","options":{"ddb_table":"' + test_ddb_table + '","parameter_key":"' + test_ddb_name_text_var + '"}}'
        lambda_client=boto3.client('lambda')
        result=lambda_client.invoke(
            FunctionName='keypot',
            InvocationType='RequestResponse',
            Payload=payload,
        )
        check_value=result['Payload'].read()
        self.assertRegexpMatches(check_value,'^\"Successfully removed.*')
        
    #TODO:  Just a nice-to-have
    # def test_list_fake_table(self):
    #     args={"ddb_table": "fake-table-81173829891199"}
    #     #expects an error
    #     with self.assertRaises(ClientError) as ce:
    #         keypot_with_region=Keypot(args).list_from_ddb()
    #     self.assertTrue(ce)
    #     

        
    
if __name__ == '__main__':
    KeypotTestSuite = unittest.TestSuite()
    
    ### Text
    #Make new entry
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_encrypt_value_no_override_empty'))
    
    #Repeat entry, but this time it should fail because it already exists
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_encrypt_value_no_override_override_failure'))
    
    #Decrypt/Read entry for correct value
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_read_text_value1'))
    
    #Overwrite the entry
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_encrypt_value_with_overwrite'))
    
    #Re-read entry to ensure it took new value
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_read_text_value2'))
    
    #Repeat entry again, but this time using Override=false flag
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_encrypt_value_override_false_override_failure'))
    
    #List all objects (should have at least 1)
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_list_function'))
    
    #Delete text value
    KeypotTestSuite.addTest(KeypotLambdaTestCase('test_delete_text_key'))
    
    ### Other Tests
    
    #Incorrect table name check
    #KeypotTestSuite.addTest(KeypotLambdaTestCase('test_list_fake_table'))
    
    ### Setup Unit Test Runner
    keypot_runner = unittest.TextTestRunner()
    
    ### Run tests
    keypot_runner.run(KeypotTestSuite)