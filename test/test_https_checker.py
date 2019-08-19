import https_checker
import unittest
import boto3

from botocore.stub import Stubber

class TestHTTPSChecker(unittest.TestCase):

  def test_anything(self):
    cloudwatch = boto3.client(
      'cloudwatch',
      region_name='marktopia',
      aws_access_key_id='ACCESS_KEY',
      aws_secret_access_key='SECRET_KEY')
    stubber = Stubber(cloudwatch)
    stubber.add_response('put_metric_data', {})# {'person_who_fails': 'mark'})
    with stubber:
      https_checker.put_cloudwatch_metric(cloudwatch, 'www.vee_ay.gov', '1.2.3.4', False)

if __name__ == '__main__':
    unittest.main()
