#!/usr/bin/python

import unittest
import boto3
from botocore.exceptions import *
from keypot import Keypot
from keypot_exceptions.KeypotError import KeypotError
import subprocess
import filecmp

#Module Variables (Global)
test_ddb_table='test-creds'
test_kms_key='alias/test-key'
test_ddb_name_text_var='unit-test-var'
test_ddb_name_text_val1='unit-test-value1'
test_ddb_name_text_val2='unit-test-value2'
test_ddb_name_file='unit-test-file'
test_private_key_name='test-private-key.pem'
test_private_key_name_output='test-private-key-output.pem'

class KeypotTestCase(unittest.TestCase):    
    
    @classmethod
    def setUpClass(self):
        print('\nBeginning test suite setup\n')
        #create a private key to test uploads
        subprocess.call(['openssl','genrsa','-out',test_private_key_name,'2048'])
        self.remove_all_ddb_entries()
    
    @classmethod
    def tearDownClass(self):
        print('\nBeginning test suite tear down\n')
        #remove the private key created in setUp
        subprocess.call(['rm','-rf',test_private_key_name])
        subprocess.call(['rm','-rf',test_private_key_name_output])
        self.remove_all_ddb_entries()
        
    @classmethod
    def remove_all_ddb_entries(self):
        #Cleans up any potential failed runs before exiting
        args={"ddb_table":test_ddb_table}
        setup_keypot=Keypot(args)
        setup_keypot.parameter_key=test_ddb_name_text_var
        print('Removing:' + str(test_ddb_name_text_var) + ' from ' + test_ddb_table )
        setup_keypot.do_delete()
        
        setup_keypot.parameter_key=test_ddb_name_file
        print('Removing:' + str(test_ddb_name_file) + ' from ' + test_ddb_table )
        setup_keypot.do_delete()
        
    def test_ddb_client_config(self):
        args={"ddb_table":test_ddb_table}
        keypot_instance=Keypot(args)
        all_tables=keypot_instance.ddb.list_tables()
        response_code=all_tables['ResponseMetadata']['HTTPStatusCode']
        self.assertEqual(response_code,200)
        
    def test_kms_client_config(self):
        args={"ddb_table":test_ddb_table}
        keypot_instance=Keypot(args)
        all_keys=keypot_instance.kms.list_keys()
        response_code=all_keys['ResponseMetadata']['HTTPStatusCode']
        self.assertEqual(response_code,200)
    
    def test_encrypt_value_no_override_empty(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var,"parameter_value":test_ddb_name_text_val1,"kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        self.assertIsInstance(keypot_instance.do_encrypt(),str)
        
    def test_encrypt_value_no_override_override_failure(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var,"parameter_value":test_ddb_name_text_val1,"kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        with self.assertRaises(KeypotError) as ke:
            keypot_instance.do_encrypt()
            
    def test_encrypt_value_override_false_override_failure(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var,"parameter_value":test_ddb_name_text_val1, "overwrite": "FALSE", "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        with self.assertRaises(KeypotError) as ke:
            keypot_instance.do_encrypt()
    
    def test_encrypt_value_with_overwrite(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var,"parameter_value":test_ddb_name_text_val2, "overwrite": "TRUE", "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        self.assertIsInstance(keypot_instance.do_encrypt(),str)
        
    def test_encrypt_file_no_override_empty(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_file,"parameter_file":test_private_key_name, "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        self.assertIsInstance(keypot_instance.do_encrypt(),str)
    
    def test_decrypt_file(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_file, "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        retreived_value=keypot_instance.do_decrypt()
        
        try:
            with open(test_private_key_name_output, "wb") as f:
                f.write(retreived_value.encode("UTF-8"))
        finally:
            if f:
                f.close()
        
        #compare both files, make sure they came out exactly the same
        self.assertTrue(filecmp.cmp(test_private_key_name,test_private_key_name_output))
        
    def test_read_text_value1(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var, "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        retreived_value=keypot_instance.do_decrypt()
        self.assertEqual(retreived_value,test_ddb_name_text_val1)
        
    def test_read_text_value2(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var, "kms_key": test_kms_key}
        keypot_instance=Keypot(args)
        retreived_value=keypot_instance.do_decrypt()
        self.assertEqual(retreived_value,test_ddb_name_text_val2)
    
    def test_list_function(self):
        args={"ddb_table": "test-creds"}
        keypot_instance=Keypot(args)
        result_list=keypot_instance.list_from_ddb()
        self.assertIsInstance(result_list, list)
        
        #based on previous tests, should have at least two values
        self.assertTrue(len(result_list)>=2)
        
    def test_list_fake_table(self):
        args={"ddb_table": "fake-table-81173829891199"}
        #expects an error
        with self.assertRaises(ClientError) as ce:
            keypot_with_region=Keypot(args).list_from_ddb()
        self.assertTrue(ce)
        
    def test_delete_text_key(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_text_var}
        keypot_instance=Keypot(args)
        self.assertIsInstance(keypot_instance.do_delete(),str)
    
    def test_delete_file_key(self):
        args={"ddb_table":test_ddb_table,"parameter_key":test_ddb_name_file}
        keypot_instance=Keypot(args)
        self.assertIsInstance(keypot_instance.do_delete(),str)
        
    
if __name__ == '__main__':
    KeypotTestSuite = unittest.TestSuite()
    #Check clients are capable of talking to AWS
    KeypotTestSuite.addTest(KeypotTestCase('test_ddb_client_config'))
    KeypotTestSuite.addTest(KeypotTestCase('test_kms_client_config'))
    
    ### Text
    #Make new entry
    KeypotTestSuite.addTest(KeypotTestCase('test_encrypt_value_no_override_empty'))
    
    #Repeat entry, but this time it should fail because it already exists
    KeypotTestSuite.addTest(KeypotTestCase('test_encrypt_value_no_override_override_failure'))
    
    #Repeat entry again, but this time using Override=false flag
    KeypotTestSuite.addTest(KeypotTestCase('test_encrypt_value_override_false_override_failure'))
    
    #Decrypt/Read entry for correct value
    KeypotTestSuite.addTest(KeypotTestCase('test_read_text_value1'))
    
    #Overwrite the entry
    KeypotTestSuite.addTest(KeypotTestCase('test_encrypt_value_with_overwrite'))
    
    #Re-read entry to ensure it took new value
    KeypotTestSuite.addTest(KeypotTestCase('test_read_text_value2'))
    
    ### File
    #Make new entry
    KeypotTestSuite.addTest(KeypotTestCase('test_encrypt_file_no_override_empty'))
    
    #Decrypt/Read entry for correct value
    KeypotTestSuite.addTest(KeypotTestCase('test_decrypt_file'))
    
    #List all objects (should have at least 2)
    KeypotTestSuite.addTest(KeypotTestCase('test_list_function'))
    
    #Delete text value
    KeypotTestSuite.addTest(KeypotTestCase('test_delete_text_key'))
    
    #Delete file value
    KeypotTestSuite.addTest(KeypotTestCase('test_delete_file_key'))
    
    ### Other Tests
    
    #Incorrect table name check
    KeypotTestSuite.addTest(KeypotTestCase('test_list_fake_table'))
    
    ### Setup Unit Test Runner
    keypot_runner = unittest.TextTestRunner()
    keypot_runner.run(KeypotTestSuite)