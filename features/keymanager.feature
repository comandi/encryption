Feature: Key Manager
  The Key Manager is responsible for managing Data Keys

  Scenario: A Key Manager can be instantiated
    Given a Key Manager
    Then I have a Key Manager

  Scenario: A Key Manager can create a Data Key
    Given a Key Manager
    When the Key Manager creates a Data Key
    Then I have a Data Key

  Scenario: A Key Manager can decrypt a Data Key
    Given a Key Manager
    When the Key Manager creates a Data Key
    And the Data Key is sealed
    And the Key Manager decrypts the Data Key
    Then the plaintext Data Keys are the same
