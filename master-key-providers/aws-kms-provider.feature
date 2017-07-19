Feature: AWS KMS Master Key Provider

  Scenario: An AWS KMS Master Key Provider can be created
    Given an "AWS-KMS" Master Key Provider
    When I instantiate the provider
    Then I have a Master Key Provider

  Scenario: The AWS KMS master key provider can generate a Master Key
    Given an "AWS-KMS" Master Key Provider
    When I instantiate the provider
    And I generate a Master Key for private label "dummy"
    Then I have a Master Key
    And the Master Key has Master Key ID "kms:1234"

  Scenario: The AWS KMS Master Key Provider can decrypt a specific Master Key
    Given an "AWS-KMS" Master Key Provider
    When I instantiate the provider
    And I generate a Master Key for private label "dummy"
    And I serialize the Master Key
    And I deserialize and decrypt the serialized Master Key
    Then the Master Key and the Deserialized Master Key are the same