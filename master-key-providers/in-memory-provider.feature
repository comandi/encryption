Feature: In-Memory Master Key Provider

  Scenario: An in-memory Master Key Provider can be created
    Given an "In-Memory" Master Key Provider
    When I instantiate the provider
    Then I have a Master Key Provider

  Scenario: The in-memory master key provider can generate a Master Key
    Given an "In-Memory" Master Key Provider
    When I instantiate the provider
    And I generate a Master Key for private label "dummy"
    Then I have a Master Key
    And the Master Key has Master Key ID "imkp:0"

  Scenario: The in-memory Master Key Provider can decrypt a specific Master Key
    Given an "In-Memory" Master Key Provider
    When I instantiate the provider
    And I generate a Master Key for private label "dummy"
    And I serialize the Master Key
    And I deserialize and decrypt the serialized Master Key
    Then the Master Key and the Deserialized Master Key are the same
