package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string;
	
	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	username string
	password []byte
	master_key []byte
	hmac_key []byte

	SecretKey userlib.PKEDecKey
	Files_owned map[string]int
	Sign_key userlib.DSSignKey
}

// This is the type definition for the OwnerMetaFile struct.
type OwnerMetaFile struct {
	Shared_with_uuids map[string]uuid.UUID
	Shared_with_enc_keys map[string][]byte
	Shared_with_hmac_keys map[string][]byte
	File_encryption_key []byte
	Hmac_key []byte
	File_pointer uuid.UUID
}

type MetaFile struct {
	File_encryption_key []byte
	Hmac_key []byte
	File_pointer uuid.UUID
}

type MetaMetaFile struct {
	Meta_file_encryption_key []byte
	Hmac_key []byte
	Hmac_tag []byte
	Meta_file_pointer uuid.UUID
}

type Invitation struct {
	Mf_decrypt_key []byte
	Mf_hmac_key []byte
	meta_file_pointer uuid.UUID
}

type File struct {
	Contents []byte
	Tail uuid.UUID
}

type FileInfo struct {
	Pointer_start uuid.UUID
	Pointer_end uuid.UUID
}

func isValidMac(data []byte, hmac_key []byte) (nice bool) {
	hmac_tag := data[len(data)-64:]
	
	var contents []byte = data[0:len(data)-64]
	
	hmac_tag_computed,_ := userlib.HMACEval(hmac_key[:16],contents)
	
	var equal bool = userlib.HMACEqual(hmac_tag,hmac_tag_computed)

	return equal
}


func UpdateUserDatastore(userdata *User) (err error) {
	user_string, err := json.Marshal(&userdata)
	if err != nil {return err}
	user_encrypted := userlib.SymEnc(userdata.master_key, userlib.RandomBytes(16), user_string)
	user_hmac, err := userlib.HMACEval(userdata.hmac_key, user_encrypted )
	if err != nil {return err}
	user_complete := append(user_encrypted,user_hmac...)
	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {return err}
	userlib.DatastoreSet(user_uuid, user_complete)
	return nil
}

//file_object is an object where the the data should be stored
//For instance, prior to the function you can write:
//var file_object File, which would be the file_object in the function
func OpenFromDataStore(file_pointer uuid.UUID,enc_key []byte,hmac_key []byte) (bytes []byte, err error){
	file_data, ok := userlib.DatastoreGet(file_pointer)
		if !ok {
			fmt.Println(file_pointer)
			return nil, errors.New(strings.ToTitle("not ok"))
		}
		if !isValidMac(file_data,hmac_key) {
			return nil, errors.New(strings.ToTitle("invalid mac in open from datastore"))
		}
	file_data = file_data[:len(file_data)-64]
	file_data_decrypted := userlib.SymDec(enc_key[:16],file_data)
	return file_data_decrypted, err
}


func PublishToDataStore(file_pointer uuid.UUID, enc_key []byte, hmac_key []byte, file_object interface{}) (err error){
	marshalled_contents, err := json.Marshal(file_object)
	
	
	enc_contents := userlib.SymEnc(enc_key[:16], userlib.RandomBytes(16), marshalled_contents)
	hmac_tag, err := userlib.HMACEval(hmac_key, enc_contents)
	if err != nil {
		return err
	}
	file_data := append(enc_contents, hmac_tag...)
	userlib.DatastoreSet(file_pointer, file_data)
	return err
}


func ReadFromFile(head_uid uuid.UUID, enc_key []byte, hmac_key []byte) (content []byte,err error){
	current_uuid := head_uid
	var keep_iter bool = true
	
	//Usikker på hvordan jeg kan deklarere en tom byte.. 
	//Kan ikke appende på "nil", men jeg vil samtidig ikke appende på en "0"
	var contents []byte
	//while there's still a tail
	for ok := true; ok; ok = (keep_iter==true) {
		var file File
		var results []byte 

		results, err = OpenFromDataStore(current_uuid,enc_key[:16],hmac_key[:16])
		if err != nil {
				return nil, err
		}
		err =json.Unmarshal(results, &file)
		if err != nil {
			return nil, err
		}

		contents = append(contents,file.Contents...)
		//fmt.Println(string(contents))
		//Må dobbeltsjekke om dette funker senere
		if file.Tail == uuid.Nil {
			keep_iter=false
			break
		} 
		current_uuid = file.Tail
	}
	return contents, nil
}
func CreateInv(meta_file_enc_key []byte, meta_file_hmac_key []byte) (inv Invitation, id uuid.UUID) {
	invitation_id := uuid.New()
	var invitation Invitation
	invitation.Mf_decrypt_key = meta_file_enc_key
	invitation.Mf_hmac_key = meta_file_hmac_key
	return invitation, invitation_id
}

func EncryptSignAndStore(invitation Invitation,invitation_id uuid.UUID, recipientUsername string, sign_key userlib.DSSignKey)(err error) {
	var userdata_marshalled, _ = json.Marshal(invitation)
	recipient_pk, ok := userlib.KeystoreGet(recipientUsername + "PublicKey")
	if ok != true {return}
	cipher_invitation, err := userlib.PKEEnc(recipient_pk, userdata_marshalled)
	
	//256 byte signature
	inv_sign, err := userlib.DSSign(sign_key, cipher_invitation)

	cipher_and_sign := append(cipher_invitation,inv_sign...)
	userlib.DatastoreSet(invitation_id, cipher_and_sign)
	return err
}

func UpdateUser(username string, hashed_pass []byte) (userdataptr *User, err error) { 
	var userdata User
	userdataptr = &userdata

	// Creates the mackey usikng HashKDF. Sourcekey is created with password, username+0. "hmacuser" is the purpose.
	salt := username+"0"
	userdata.username = username
	userdata.password = hashed_pass

	master_key := userlib.Argon2Key([]byte(userdata.password),[]byte(salt), keyLen)[:16]
	macKey_long, err := userlib.HashKDF(master_key, []byte("hmacuser"))
	hmac_key := macKey_long[:16]


	// Finds UUID for the User-struct.
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// Retrives data from the datastore.
	datastore_string, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	
	data_contents := datastore_string[:len(datastore_string)-64]
	hmac_tag  := datastore_string[len(datastore_string)-64:]

	// Created what the HMAC of the message is now.
	hmac_check, err := userlib.HMACEval(hmac_key, data_contents)
	if err != nil {
		return nil, err
	}

	// Checks if HMAC now and HMAC in the message corrosponds.
	if ! userlib.HMACEqual(hmac_tag, hmac_check) {
		return nil, errors.New("HAMC tag is wrong.")
	}
	data_content_decrypted := userlib.SymDec(master_key, data_contents)

	err = json.Unmarshal(data_content_decrypted, &userdata)
	if err != nil {
		return nil, err
	}
	userdata.master_key = master_key
	userdata.hmac_key = hmac_key
	userdata.username = username
	

	return userdataptr, nil
}



const keyLen = 16

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		return nil, errors.New(strings.ToTitle("username can't be empty"))
	}
	salt := username+"0"
	salt2 := username+"1"

	userdata.username = username
	userdata.password = userlib.Hash([]byte(password+salt2))
	//Do I have to check whether or not this user already exists???
	//Have not done this yet, can be done by checking the KeyStore

	userdata.Files_owned = make(map[string]int)

	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	//Create the master key
	pk, sk, _ = userlib.PKEKeyGen()
	userdata.SecretKey = sk
	sign_key, verify_key ,_ := userlib.DSKeyGen()
	userdata.Sign_key = sign_key

	//Derive the master key, it says in the text that the password must have better entropy, so.. 
	//Should we add a lot of garbage characters to this one?
	master_key := userlib.Argon2Key([]byte(userdata.password),[]byte(salt), keyLen)[:16]
	userdata.master_key = master_key

	hmac_key_long, err := userlib.HashKDF(master_key, []byte("hmacuser"))
	if err != nil {
		return nil, err
	}
	hmac_key := hmac_key_long[:16]
	userdata.hmac_key = hmac_key
	

	username_id := username + "PublicKey"
	_, ok := userlib.KeystoreGet(username_id)
	if ok != false {
		return nil, errors.New(strings.ToTitle("user already exists"))
	}
	//Must now put the public key in the KeyStore
	err = userlib.KeystoreSet(username_id, pk)
	if err != nil {
		return nil, err
	}
	username_verification_id := username +"VerifyKey"
	err = userlib.KeystoreSet(username_verification_id, verify_key)
	if err != nil {
		return nil, err
	}
	//Must also put the info I need in the DataStore
	//Use symmetric key encryption here
	// b MUST be a 16 lenghted slice.. Can solve this by hasihing username -> 16 length thing
	b := userlib.Hash([]byte(username))[:16]
	dataStore_user_id, err := uuid.FromBytes(b)
	if err!= nil {return nil, err}
	
	
	userdata_marshalled, err := json.Marshal(userdata)
	if err!= nil {return nil, err}
	
	var userdata_marshalled_encrypted = userlib.SymEnc(master_key, userlib.RandomBytes(16), userdata_marshalled)

	//The Hmac tag is 64 bytes!
	hmac_tag,err := userlib.HMACEval(hmac_key, userdata_marshalled_encrypted )
	if err!= nil {return nil, err}
	var userdata_marshalled_encrypted_with_mac = append(userdata_marshalled_encrypted,hmac_tag...)

	userlib.DatastoreSet(dataStore_user_id, userdata_marshalled_encrypted_with_mac)


	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Creates the mackey usikng HashKDF. Sourcekey is created with password, username+0. "hmacuser" is the purpose.
	salt := username+"0"
	salt2 := username+"1"
	userdata.username = username
	userdata.password = userlib.Hash([]byte(password+salt2))

	master_key := userlib.Argon2Key([]byte(userdata.password),[]byte(salt), keyLen)[:16]
	macKey_long, err := userlib.HashKDF(master_key, []byte("hmacuser"))
	hmac_key := macKey_long[:16]

	username_id := username + "PublicKey"
	_, ok := userlib.KeystoreGet(username_id)
	if ok == false {
		return nil, errors.New(strings.ToTitle("user does not exist"))
	}

	// Finds UUID for the User-struct.
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// Retrives data from the datastore.
	datastore_string, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	
	data_contents := datastore_string[:len(datastore_string)-64]
	hmac_tag  := datastore_string[len(datastore_string)-64:]


	// Created what the HMAC of the message is now.
	//IF they credentials of the user are wrong, this will throw an error
	hmac_check, err := userlib.HMACEval(hmac_key, data_contents)
	if err != nil {
		return nil, err
	}

	// Checks if HMAC now and HMAC in the message corrosponds.
	if ! userlib.HMACEqual(hmac_tag, hmac_check) {
		return nil, errors.New("HAMC tag is wrong.")
	}
	data_content_decrypted := userlib.SymDec(master_key, data_contents)

	err = json.Unmarshal(data_content_decrypted, &userdata)
	if err != nil {
		return nil, err
	}

	userdata.master_key = master_key
	userdata.hmac_key = hmac_key
	userdata.username = username
	

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	userdata , err = UpdateUser(userdata.username, userdata.password)
	if err != nil {return err}


	contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
	file_uuid, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
	if err != nil { 
		return err
	}

	datastore_contents, ok := userlib.DatastoreGet(file_uuid)

	// When the file does not exist already
	if !ok {
		// Create MetaFile. 
		userdata.Files_owned[filename] = 1
		// Updates the User-instance in the datastore after it is changed. 
		err := UpdateUserDatastore(userdata)
		
		if err != nil {return err}
		var meta_file OwnerMetaFile
		var file_info FileInfo
		var file File
		var file1 File

		meta_file.File_encryption_key = userlib.RandomBytes(16)
		meta_file.Hmac_key = userlib.RandomBytes(16)
		meta_file.File_pointer = uuid.New()
		meta_file.Shared_with_uuids = make(map[string]uuid.UUID)
		meta_file.Shared_with_enc_keys = make(map[string][]byte)
		meta_file.Shared_with_hmac_keys = make(map[string][]byte)

		hmac_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "hmac"))
		hmac_key = hmac_key[0:16]
		
		if err != nil {
			return err
		}
		enc_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "enc_key"))
		if err != nil {
			return err
		}
		marshalled_meta_file, err := json.Marshal(meta_file)
		if err != nil {
			return err
		}
		enc_meta_file := userlib.SymEnc(enc_key[:16], userlib.RandomBytes(16), marshalled_meta_file)
		meta_file_hmac, err := userlib.HMACEval(hmac_key, enc_meta_file)
		if err != nil {
			return err
		}
		meta_file_and_hmac := append(enc_meta_file, meta_file_hmac...)
		

		userlib.DatastoreSet(file_uuid, meta_file_and_hmac)

		file_info.Pointer_start = uuid.New()
		file_info.Pointer_end = uuid.New()
		marshalled_file_info, err := json.Marshal(file_info)
		if err != nil {
			return err
		}
		enc_file_info := userlib.SymEnc(meta_file.File_encryption_key[:16], userlib.RandomBytes(16), marshalled_file_info)
		file_info_hmac, err := userlib.HMACEval(meta_file.Hmac_key, enc_file_info)
		if err != nil {
			return err
		}
		file_info_and_hmac := append(enc_file_info, file_info_hmac...)

		userlib.DatastoreSet(meta_file.File_pointer, file_info_and_hmac)

		file.Contents = content 
		file.Tail = file_info.Pointer_end
		marshalled_file, err := json.Marshal(file)
		if err != nil {
			return err
		}
		enc_file := userlib.SymEnc(meta_file.File_encryption_key[:16], userlib.RandomBytes(16), marshalled_file)
		file_hmac, err := userlib.HMACEval(meta_file.Hmac_key, enc_file)
		if err != nil {
			return err
		}
		file_and_hmac := append(enc_file, file_hmac...)

		userlib.DatastoreSet(file_info.Pointer_start, file_and_hmac)

		marshalled_file1, err := json.Marshal(file1)
		enc_file1 := userlib.SymEnc(meta_file.File_encryption_key[:16], userlib.RandomBytes(16), marshalled_file1)
		file_hmac1, err := userlib.HMACEval(meta_file.Hmac_key, enc_file1)
		if err != nil {
			return err
		}
		file_and_hmac1 := append(enc_file1, file_hmac1...)

		userlib.DatastoreSet(file_info.Pointer_end, file_and_hmac1)

		return nil
	}


	hmac_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "hmac"))
	if err !=nil {return err}
	hmac_key = hmac_key[:16]
	enc_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "enc_key"))
	if err !=nil {return err}
	// When the user is the owner of the file
	if val, ok := userdata.Files_owned[filename]; ok {
		var owner_meta_file OwnerMetaFile
		var file_info FileInfo
		_ = val
		// Open OwnerMetaFile
		if ! isValidMac(datastore_contents, hmac_key) {
			return errors.New("someone tampered with the OwnerMetafile")
		}
		data_contents_omf := datastore_contents[:len(datastore_contents)-64]
		
		dec_data_contents_omf := userlib.SymDec(enc_key[:16], data_contents_omf)
		err := json.Unmarshal(dec_data_contents_omf, &owner_meta_file)
		if err != nil {
			return errors.New("something is not quite right with the OwnerMetaFile.")
		}

		// Open InfoFile
		datastore_contents_fi, ok := userlib.DatastoreGet(owner_meta_file.File_pointer)
		if !ok {
			return errors.New("Cannot get file info ")
		}
		if ! isValidMac(datastore_contents_fi, owner_meta_file.Hmac_key) {
			return errors.New("someone tampered with the infofile")
		}
		data_contents_fi := datastore_contents_fi[:len(datastore_contents_fi)-64]
		dec_data_contents_fi := userlib.SymDec(owner_meta_file.File_encryption_key[:16], data_contents_fi)
		err = json.Unmarshal(dec_data_contents_fi, &file_info)
		if err != nil {
			return errors.New("something is not quite right with the FileInfo.")
		}
	

		// Post to File

		var file1 File
		var file2 File
		file1.Contents = content
		file1.Tail = uuid.New()

		file1_content_marshalled, err := json.Marshal(file1)
		if err != nil {return err}
		file1_content_enc := userlib.SymEnc(owner_meta_file.File_encryption_key[:16], userlib.RandomBytes(16), file1_content_marshalled)
		file1_hmac, err := userlib.HMACEval(owner_meta_file.Hmac_key, file1_content_enc)
		if err != nil {return err}
		file1_complete := append(file1_content_enc, file1_hmac...)
		userlib.DatastoreSet(file_info.Pointer_start, file1_complete)

		// Empty tail at end of the file
		file2_content_marshalled, err := json.Marshal(file2)
		if err != nil {return err}
		file2_content_enc := userlib.SymEnc(owner_meta_file.File_encryption_key[:16], userlib.RandomBytes(16), file2_content_marshalled)
		file2_hmac, err := userlib.HMACEval(owner_meta_file.Hmac_key, file2_content_enc)
		if err != nil {return err}
		file2_complete := append(file2_content_enc, file2_hmac...)
		userlib.DatastoreSet(file1.Tail, file2_complete)

		return nil
	}

	// When the user is not the owner of the file
	var meta_meta_file MetaMetaFile
	var meta_file MetaFile
	var file_info FileInfo

	// Open OwnerMetaMetaFile
	if ! isValidMac(datastore_contents, hmac_key) {
		return errors.New("someone tampered with the MetaMetaFile")
	}
	data_contents_mmf := datastore_contents[:len(datastore_contents)-64]
	
	dec_data_contents_mmf := userlib.SymDec(enc_key[:16], data_contents_mmf)
	err = json.Unmarshal(dec_data_contents_mmf, &meta_meta_file)
	if err != nil {
		return errors.New("something is not quite right with the MetaMetaFile.")
	}

	// Open MetaFile
	datastore_contents_mf, ok := userlib.DatastoreGet(meta_meta_file.Meta_file_pointer)
	if !ok {
		return errors.New("Cannot retrieve MetaFile")
	}
	if ! isValidMac(datastore_contents_mf, meta_meta_file.Hmac_key) {
		return errors.New("someone tampered with the MetaFile")
	}
	data_contents_mf := datastore_contents_mf[:len(datastore_contents_mf)-64]
	dec_data_contents_mf := userlib.SymDec(meta_meta_file.Meta_file_encryption_key[:16], data_contents_mf)
		
	err = json.Unmarshal(dec_data_contents_mf, &meta_file)
	if err != nil {
		return errors.New("something is not quite right with the MetaFile.")
	}

	// Open FileInfo
	datastore_contents_fi, ok := userlib.DatastoreGet(meta_file.File_pointer)
	if !ok {
		return errors.New("cannot retrieve fileinfo")
	}
	if ! isValidMac(datastore_contents_fi, meta_file.Hmac_key) {
		return errors.New("someone tampered with the infofile")
	}
	data_contents_fi := datastore_contents_fi[:len(datastore_contents_fi)-64]
	dec_data_contents_fi := userlib.SymDec(meta_file.File_encryption_key[:16], data_contents_fi)
	
	err = json.Unmarshal(dec_data_contents_fi, &file_info)
	if err != nil {
		return errors.New("something is not quite right with the FileInfo.")
	}

	// Post to File
	var file1 File
	var file2 File
	file1.Contents = content
	file1.Tail = uuid.New()

	file1_content_marshalled, err := json.Marshal(file1)
	if err != nil {return err}
	file1_content_enc := userlib.SymEnc(meta_file.File_encryption_key[:16], userlib.RandomBytes(16), file1_content_marshalled)
	file1_hmac, err := userlib.HMACEval(meta_file.Hmac_key, file1_content_enc)
	if err != nil {return err}
	file1_complete := append(file1_content_enc, file1_hmac...)
	userlib.DatastoreSet(file_info.Pointer_start, file1_complete)

	// Empty tail at end of the file
	file2_content_marshalled, err := json.Marshal(file2)
	if err != nil {return err}
	file2_content_enc := userlib.SymEnc(meta_file.File_encryption_key[:16], userlib.RandomBytes(16), file2_content_marshalled)
	file2_hmac, err := userlib.HMACEval(meta_file.Hmac_key, file2_content_enc)
	if err != nil {return err}
	file2_complete := append(file2_content_enc, file2_hmac...)
	userlib.DatastoreSet(file1.Tail, file2_complete)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var results []byte
	userdata ,_= UpdateUser(userdata.username, userdata.password)
	contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
	file_uuid, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
	if err != nil { 
		return err
	}

	hmac_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "hmac"))
	hmac_key = hmac_key[:16]
	
	enc_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "enc_key"))
	if err!=nil {return err}
	// When you are the owner of the File
	if val, ok := userdata.Files_owned[filename]; ok {
		_ = val
		// Open OwnerMetaFile
		var owner_meta_file OwnerMetaFile
		

		results, err := OpenFromDataStore(file_uuid, enc_key, hmac_key)
		if err!=nil{return err}
		err = json.Unmarshal(results, &owner_meta_file)
		if err != nil {return err}
		// Open InfoFile
		var file_info FileInfo

		
		results, err =OpenFromDataStore(owner_meta_file.File_pointer, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key)
		if err!=nil{return err}
		err = json.Unmarshal(results, &file_info)
		if err != nil {return err}

		// Add the contents
		//var file File
		var file1 File
		var file2 File
		
		file1.Contents = content
		file1.Tail = uuid.New()

		PublishToDataStore(file_info.Pointer_end, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key, file1)

		// Update InfoFile to contain the new tail
		file_info.Pointer_end = file1.Tail
		PublishToDataStore(owner_meta_file.File_pointer, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key, file_info)

		// Publish empty file for tail
		PublishToDataStore(file1.Tail, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key, file2)
		
		return nil
	}


	// Open MetaMetaFile
	var meta_meta_file MetaMetaFile
	results, err = OpenFromDataStore(file_uuid, enc_key, hmac_key)
	if err!=nil{return err}
	err = json.Unmarshal(results, &meta_meta_file)
	if err != nil {return err}
	// Open MetaFile
	var meta_file MetaFile
	results, err = OpenFromDataStore(meta_meta_file.Meta_file_pointer, meta_meta_file.Meta_file_encryption_key, meta_meta_file.Hmac_key)
	if err!=nil{return err}
	err = json.Unmarshal(results, &meta_file)
	if err != nil {return err}
	// Open InfoFile
	var file_info FileInfo
	results, err = OpenFromDataStore(meta_file.File_pointer, meta_file.File_encryption_key, meta_file.Hmac_key)
	if err!=nil{return err}
	err = json.Unmarshal(results, &file_info)
	if err != nil {return err}
	// Add the contents
	var file1 File
	var file2 File
	file1.Contents = content
	file1.Tail = uuid.New()
	PublishToDataStore(file_info.Pointer_end, meta_file.File_encryption_key, meta_file.Hmac_key, file1)

	// Update InfoFile to contain the new tail
	file_info.Pointer_end = file1.Tail
	PublishToDataStore(meta_file.File_pointer, meta_file.File_encryption_key, meta_file.Hmac_key, file_info)

	// Publish empth file for tail
	PublishToDataStore(file_info.Pointer_end, meta_file.File_encryption_key, meta_file.Hmac_key, file2)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var results []byte
	userdata ,err= UpdateUser(userdata.username, userdata.password)
	if err!=nil{return nil, err}
	contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
	storageKey, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
	if err!=nil{return nil, err}
	decryption_key,_ := userlib.HashKDF(userdata.master_key, []byte(filename+"enc_key") ) 
	hmac_key,err := userlib.HashKDF(userdata.master_key, []byte(filename+"hmac"))
	if err!=nil{return nil, err}
	hmac_key = hmac_key[:16]

	data, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	if !isValidMac(data,hmac_key) {
		return nil, errors.New(strings.ToTitle("invalid mac"))
	}
	//Just remove the HMAC

	data = data[:len(data)-64]


	//You are the owner of the file
	if _, ok := userdata.Files_owned[filename]; ok {

		var owner_meta_file OwnerMetaFile
		data_decrypted := userlib.SymDec(decryption_key[:16], data)
		err = json.Unmarshal(data_decrypted, &owner_meta_file)
		if err != nil { return nil, err }
		var info_file_struct FileInfo
		
		results, err = OpenFromDataStore(owner_meta_file.File_pointer,owner_meta_file.File_encryption_key ,owner_meta_file.Hmac_key)
		if err != nil { return nil, err }
		err = json.Unmarshal(results,&info_file_struct)
		if err != nil { return nil, err}
		
		content ,err:= ReadFromFile(info_file_struct.Pointer_start, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key)
		if err != nil { return nil, err}
		return content, err
	} else { //You are not the owner of the file
		var meta_meta_file MetaMetaFile
		decrypted_data := userlib.SymDec(decryption_key[:16], data)
		err = json.Unmarshal(decrypted_data, &meta_meta_file)
		if err != nil { return }

		//Husk å dobbeltsjekke om man kan sende inn structen, og ta addressen av den senere
		//Eller om man må sende inn addressen til den i OpenFromDataStore
		var meta_file_struct MetaFile
		fmt.Println(meta_meta_file.Meta_file_pointer)
		results, err = OpenFromDataStore(meta_meta_file.Meta_file_pointer, meta_meta_file.Meta_file_encryption_key, meta_meta_file.Hmac_key)
		if err != nil { return }
		err = json.Unmarshal(results, &meta_file_struct)
		//Skal nå åpne info_structen
		var info_file_struct FileInfo
		results, err = OpenFromDataStore(meta_file_struct.File_pointer, meta_file_struct.File_encryption_key, meta_file_struct.Hmac_key)
		if err != nil { return }
		err =json.Unmarshal(results, &info_file_struct)
		if err!=nil{return nil, err}
		content,err := ReadFromFile(info_file_struct.Pointer_start,meta_file_struct.File_encryption_key,meta_file_struct.Hmac_key)
		if err!=nil{return nil, err}
		return content, err
	}
}

//NB: Må fikse helt perfekt error handling, som står i specen
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
		userdata ,err= UpdateUser(userdata.username, userdata.password)
		if err!= nil {return uuid.Nil, err}
		contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
		storageKey, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
		if err!= nil {return uuid.Nil, err}
		decryption_key,err := userlib.HashKDF(userdata.master_key, []byte(filename+"enc_key") ) 
		if err!= nil {return uuid.Nil, err}
		hmac_key, err:= userlib.HashKDF(userdata.master_key, []byte(filename+"hmac"))
		if err!= nil {return uuid.Nil, err}

		if err != nil {return uuid.Nil, err}
		hmac_key = hmac_key[:16]

	
		data, ok := userlib.DatastoreGet(storageKey)
		
		if !ok {
			return uuid.Nil, errors.New(strings.ToTitle("file not found"))
		}
	
		if !isValidMac(data,hmac_key) {
			return uuid.Nil, errors.New(strings.ToTitle("invalid mac"))
		}
		//Just remove the HMAC
		data = data[:len(data)-64]

		//If you are the owner of the file:
		//Data is then the Meta_owner_file
		username_id := recipientUsername + "PublicKey"
		_, ok = userlib.KeystoreGet(username_id)
		if ok == false {
			return uuid.Nil, errors.New(strings.ToTitle("user does not exist"))
		}
	
		if _, ok := userdata.Files_owned[filename]; ok {
			//Load the owner meta file
			var owner_meta_file OwnerMetaFile
			data_decrypted := userlib.SymDec(decryption_key[:16], data)
			err = json.Unmarshal(data_decrypted, &owner_meta_file)
			if err != nil { return uuid.Nil , err }

			var new_meta_file MetaFile
			new_meta_file.File_encryption_key = owner_meta_file.File_encryption_key
			new_meta_file.Hmac_key = owner_meta_file.Hmac_key
			new_meta_file.File_pointer = owner_meta_file.File_pointer

			meta_enc_key := userlib.RandomBytes(16)
			meta_hmac_key := userlib.RandomBytes(16)


			new_meta_file_uuid,_ := uuid.FromBytes(userlib.Hash(meta_enc_key)[:16])
			
			owner_meta_file.Shared_with_uuids[recipientUsername] = new_meta_file_uuid
			owner_meta_file.Shared_with_enc_keys[recipientUsername] = meta_enc_key
			owner_meta_file.Shared_with_hmac_keys[recipientUsername] = meta_hmac_key

			err = PublishToDataStore(storageKey, decryption_key, hmac_key, owner_meta_file)
			if err != nil { return uuid.Nil, err }

			err = PublishToDataStore(new_meta_file_uuid, meta_enc_key, meta_hmac_key, new_meta_file)
			if err != nil { return  uuid.Nil, err}

			invitation, invitation_id := CreateInv(meta_enc_key, meta_hmac_key)
			err := EncryptSignAndStore(invitation,invitation_id, recipientUsername, userdata.Sign_key)
			if err!= nil {return uuid.Nil, err}
			return invitation_id, err
			
		} else {
			var meta_meta_file MetaMetaFile
			var results []byte
			decrypted_data := userlib.SymDec(decryption_key[:16], data)
			err = json.Unmarshal(decrypted_data, &meta_meta_file)
			if err != nil { return uuid.Nil, err }

			var meta_file_struct MetaFile
			
			results, err = OpenFromDataStore(meta_meta_file.Meta_file_pointer, meta_meta_file.Meta_file_encryption_key, meta_meta_file.Hmac_key)
			if err != nil { return  uuid.Nil, err}
			err = json.Unmarshal(results, &meta_file_struct)
			if err!= nil {return uuid.Nil, err}

			invitation, invitation_id := CreateInv(meta_meta_file.Meta_file_encryption_key, meta_meta_file.Hmac_key)
			err := EncryptSignAndStore(invitation,invitation_id ,recipientUsername, userdata.Sign_key)
			if err!= nil {return uuid.Nil, err}
			return invitation_id, err
	
		}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//First ensure that the file already doesn't exist in the users namespace
	userdata ,err := UpdateUser(userdata.username, userdata.password)
	if err != nil {return err}
	contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
	file_uuid, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
	if err != nil { 
		return err
	}
	datastore_contents, ok := userlib.DatastoreGet(file_uuid)
	_ = datastore_contents
	if ok {
		return errors.New(strings.ToTitle("The file already exists in your namespace"))
	 }

	sender_verification_key, ok := userlib.KeystoreGet(senderUsername +"VerifyKey")
	if !ok{
		return errors.New(strings.ToTitle("Could not find senders verification key"))
	}
	inv_cipher, ok := userlib.DatastoreGet(invitationPtr)
	if !ok{
		return errors.New(strings.ToTitle("Could not find the invitation"))
	}
	inv_signature := inv_cipher[len(inv_cipher)-256:]
	inv_data := inv_cipher[:len(inv_cipher)-256]



	err = userlib.DSVerify(sender_verification_key, inv_data, inv_signature)
	if err != nil {
		return errors.New(strings.ToTitle("Invalid signature"))
	}
	inv_plaintext, err := userlib.PKEDec(userdata.SecretKey, inv_data)
	if err != nil {
		fmt.Println("ERR")
		return err
	}
	var invitation Invitation
	err = json.Unmarshal(inv_plaintext, &invitation)
	if err != nil {
		fmt.Println("wrong marshaling")
		return err
	}
	//Must check if the metafile still exists
	mini_meta_id, err := uuid.FromBytes(userlib.Hash(invitation.Mf_decrypt_key)[:16])
	_, ok = userlib.DatastoreGet(mini_meta_id)
	if !ok{
		return errors.New(strings.ToTitle("Could not find the meta file, maybe it has been revocated"))
	}


	//Must make the MetaMetaFile
	var meta_meta_file MetaMetaFile
	meta_meta_file.Meta_file_encryption_key = invitation.Mf_decrypt_key
	meta_meta_file.Hmac_key = invitation.Mf_hmac_key

	meta_meta_file.Meta_file_pointer ,err= uuid.FromBytes(userlib.Hash(meta_meta_file.Meta_file_encryption_key)[:16])
	if err!= nil {return err}


	hmac_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "hmac"))
	hmac_key = hmac_key[:16]
	if err != nil {
		return err
	}
	enc_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "enc_key"))
	if err != nil {
		return err
	}
	marshalled_meta_meta_file, err := json.Marshal(meta_meta_file)
	enc_meta_meta_file := userlib.SymEnc(enc_key[:16], userlib.RandomBytes(16), marshalled_meta_meta_file)
	meta_meta_file_hmac, err := userlib.HMACEval(hmac_key, enc_meta_meta_file)
	meta_meta_file_and_hmac := append(enc_meta_meta_file, meta_meta_file_hmac...)
	userlib.DatastoreSet(file_uuid, meta_meta_file_and_hmac)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Check if user is the ownerof the file
	userdata ,err := UpdateUser(userdata.username, userdata.password)
	if err != nil {return err}
	var results []byte
	if val, ok := userdata.Files_owned[filename]; !ok {
		_ = val
		return errors.New("You dont own a file with that name")
	}

	contents_for_uuid := append(userlib.Hash([]byte(userdata.username)), append(userlib.Hash([]byte(userdata.password)), userlib.Hash([]byte(filename))...)...)
	file_uuid, err := uuid.FromBytes(userlib.Hash(contents_for_uuid)[:16])
	if err != nil { 
		return err
	}

	// Open the OwnerMetaFile
	hmac_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "hmac"))
	if err != nil {return err}
	hmac_key = hmac_key[:16]
	enc_key, err := userlib.HashKDF(userdata.master_key, []byte(filename + "enc_key"))
	if err != nil {return err}

	var owner_meta_file OwnerMetaFile
	results, err =OpenFromDataStore(file_uuid, enc_key, hmac_key)
	if err != nil {return err}
	err = json.Unmarshal(results, &owner_meta_file)
	if err != nil {return err}

	// Check if the file is shared with the recipent already
	if val, ok := owner_meta_file.Shared_with_uuids[recipientUsername]; !ok {
		_ = val
		return errors.New("The file was never shared with that user")
	}
	//Must delete the metafile
	meta_file_uuid := owner_meta_file.Shared_with_uuids[recipientUsername]
	userlib.DatastoreDelete(meta_file_uuid)
	// Delete the revoked user from the list
	delete(owner_meta_file.Shared_with_uuids, recipientUsername)
	delete(owner_meta_file.Shared_with_enc_keys, recipientUsername)
	delete(owner_meta_file.Shared_with_hmac_keys, recipientUsername)
	// Create new keys
	new_file_enc_key := userlib.RandomBytes(16)
	new_file_hmac_key := userlib.RandomBytes(16)
	new_file_uuid := uuid.New()
	
	// Iterate over the other MetaFiles with access, and change the enckey, hmackey, uuid.
	for i, element := range owner_meta_file.Shared_with_uuids {
		_ = element
		var meta_file MetaFile
		results, err =OpenFromDataStore(owner_meta_file.Shared_with_uuids[i],owner_meta_file.Shared_with_enc_keys[i], owner_meta_file.Shared_with_hmac_keys[i])
		if err != nil {return err}
		err = json.Unmarshal(results, &meta_file)
		if err != nil {return err}
		meta_file.File_encryption_key = new_file_enc_key
		meta_file.Hmac_key = new_file_hmac_key
		meta_file.File_pointer = new_file_uuid
		PublishToDataStore(owner_meta_file.Shared_with_uuids[i],owner_meta_file.Shared_with_enc_keys[i], owner_meta_file.Shared_with_hmac_keys[i], meta_file)
	}
	// Create new FileInfo
	var file_info FileInfo
	results, err = OpenFromDataStore(owner_meta_file.File_pointer, owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key)
	if err != nil {return err}
	err = json.Unmarshal(results, &file_info)
	if err != nil {return err}
	current_uuid := file_info.Pointer_start // Used to iterate over the other files later
	file_info.Pointer_start = uuid.New()
	file_info.Pointer_end = uuid.New()
	PublishToDataStore(new_file_uuid,new_file_enc_key,new_file_hmac_key,file_info)

	
	// Create new Files

	contents, err := ReadFromFile(current_uuid,owner_meta_file.File_encryption_key, owner_meta_file.Hmac_key)
	if err != nil {return err}
	var file1 File
	var file2 File
	file1.Contents = contents
	file1.Tail = file_info.Pointer_end

	PublishToDataStore(file_info.Pointer_start,new_file_enc_key,new_file_hmac_key,file1)
	PublishToDataStore(file_info.Pointer_end,new_file_enc_key,new_file_hmac_key,file2)

	
	// Delete old files
	var keep_iter bool = true
	//while there's still a tail
	for ok := true; ok; ok = (keep_iter==true) {
		var file File
		//Just an empty file to check whether a tail is empty
		
		results, err = OpenFromDataStore(current_uuid,owner_meta_file.File_encryption_key,owner_meta_file.Hmac_key)
		if err != nil {return err}
		err = json.Unmarshal(results, &file)
		if err != nil {
				return err
		}
		//Må dobbeltsjekke om dette funker senere
		userlib.DatastoreDelete(current_uuid)
		if file.Tail == uuid.Nil {
			keep_iter=false
			break
		} 
		current_uuid = file.Tail
	}
	// Delete FileInfo
	userlib.DatastoreDelete(owner_meta_file.File_pointer)
	owner_meta_file.File_encryption_key = new_file_enc_key
	owner_meta_file.Hmac_key = new_file_hmac_key
	owner_meta_file.File_pointer = new_file_uuid


	PublishToDataStore(file_uuid,enc_key,hmac_key,owner_meta_file)
	return nil
}