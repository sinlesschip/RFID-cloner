
#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         9           
#define SS_PIN          10          

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

byte buffer[18];
byte block;
byte card_data[64][16];
MFRC522::StatusCode status;
    
MFRC522::MIFARE_Key m_key_a;
MFRC522::MIFARE_Key m_key_b;

//Variables to be set to your card
byte default_key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
byte key_a[6] = {0x07, 0x34, 0xbf, 0xb9, 0x3d, 0xab};
byte key_b[6] = {0x85, 0xa4, 0x38, 0xf7, 0x2a, 0x8a};
byte auth_blocks = 15;
byte default_blocks = 64 - (63-auth_blocks);


char choice;
/*
 * Initialize.
 */
void setup() {
    Serial.begin(9600);         // Initialize serial communications with the PC
    while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();                // Init SPI bus
    mfrc522.PCD_Init();         // Init MFRC522 card

    Serial.println("1.Copy data from card \n2.Display copied data \n3.Copy the data to new card.");

}

/*
 * Main loop.
 */
void loop() {
  choice = Serial.read();
  
  if(choice == '1')
  {
    Serial.println("Reading the card");
    read_card_and_cp_to_buffer();
    }
    else if(choice == '2')
    {
      //See copied details
      dump_card_buffer();
      Serial.println("1.Copy data from card \n2.Display copied data \n3.Copy the data to new card.");
    }
    else if(choice == '3')
    {
      Serial.println("Copying the data on to the new card");
      cp_buffer_to_card();
    }
  
}

void set_key(MFRC522::MIFARE_Key *key, byte *new_key) {
  Serial.println("\nSetting key...");
  for (byte i = 0; i < 6; i++) (*key).keyByte[i] = new_key[i];
      Serial.print("Key: ");
    dump_byte_array((*key).keyByte, 6);
    Serial.println();
}
 
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

void dump_card_buffer() {
      for (byte i=0; i<64; i++) {
        Serial.print("Block: ");
        Serial.print(i);
        Serial.println();
        for (byte j=0; j<16; j++) {
          Serial.print(card_data[i][j]);
        }
        Serial.println();
  }
}

void copy_blocks_from_buffer(byte start, byte end, MFRC522::MIFARE_Key *key_a, MFRC522::MIFARE_Key *key_b) {
  for(byte i = start; i < end+1; i++){ //Copy the blocks 1 to 63, except for all these blocks below (because these are the authentication blocks, and block 0 is mfr block)
    if(i==0 || i==3 || i == 7 || i == 11 || i == 15 || i == 19 || i == 23 || i == 27 || i == 31 || i == 35 || i == 39 || i == 43 || i == 47 || i == 51 || i == 55 || i == 59 || i == 63){
      i++;
    }
    if (i > end) {
      return;
    }
    block = i;
    
      // Authenticate using key A
    Serial.println(F("Authenticating using key A..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key_a, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    
    // Authenticate using key B
    Serial.println(F("Authenticating again using key B..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, key_b, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    
    // Write data to the block
    Serial.print(F("Writing data into block ")); 
    Serial.print(block);
    Serial.println("\n");
          
    dump_byte_array(card_data[block], 16); 
    
          
     status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, card_data[block], 16);
      if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Write() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
      }
    
        
     Serial.println("\n");
     
  }
}

void cp_buffer_to_card(){ //Copy the data in the new card
Serial.println("Insert new card...");
  // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));
  

    set_key(&m_key_a, key_a);
    set_key(&m_key_b, key_b);
    copy_blocks_from_buffer(1, 15, &m_key_a, &m_key_b);
    set_key(&m_key_a, default_key);
    copy_blocks_from_buffer(16, 63, &m_key_a, &m_key_a);
  
  
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  
  Serial.println("1.Copy data from card \n2.Display copied data \n3.Copy the data to new card.");
}

void copy_blocks_to_buffer(byte start_block, byte end_block, MFRC522::MIFARE_Key *key) {
    for(byte block = start_block; block < end_block+1; block++){

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    // Read block
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    else {
        // Successful read
        Serial.print(F("Success with key:"));
        dump_byte_array((*key).keyByte, MFRC522::MF_KEY_SIZE);
        Serial.println();
        
        // Dump block data
        Serial.print(F("Block ")); Serial.print(block); Serial.print(F(":"));
        dump_byte_array(buffer, 16); //convert from hex to asci
        Serial.println();
        
        for (int p = 0; p < 16; p++) //Read the 16 bits from the block
        {
          card_data [block][p] = buffer[p];
          Serial.print(card_data[block][p]);
          Serial.print(" ");
        }
        Serial.println();
        
        }
    }
}

void read_card_and_cp_to_buffer(){ //Read card
  Serial.println("Insert card...");
  // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
        return;

    
    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));
    
    set_key(&m_key_a, key_a);
    copy_blocks_to_buffer(0, auth_blocks, &m_key_a);  
    set_key(&m_key_a, default_key);
    copy_blocks_to_buffer(default_blocks, 63, &m_key_a);
    Serial.println();
    
    Serial.println("1.Copy data from card \n2.Display copied data \n3.Copy the data to new card.");
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  
    
}
