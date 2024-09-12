use std::cell::RefCell;
use std::fs::create_dir_all;
use std::path::Path;

use grin_core::ser;
use grin_core::ser::Error as CoreError;
use grin_store::Store;
use grin_store::{self, option_to_not_found, to_key};

use super::types::{AddressBookBackend, AddressBookBatch, Contact};
use common::Error;
use grin_wallet_impls::Address;

const DB_DIR: &'static str = "contacts";
const CONTACT_PREFIX: u8 = 'X' as u8;

pub struct Backend {
    db: grin_store::Store,
}

impl Backend {
    pub fn new(data_path: &str) -> Result<Self, Error> {
        let db_path = Path::new(data_path).join(DB_DIR);
        create_dir_all(&db_path)?;

        let store = match Store::new(db_path.to_str().unwrap(), None, Some(DB_DIR), None) {
            Ok(store) => store,
            Err(err) => {
                println!(
                    "Error: Unable to open contacts DB, storage is corrupted, {}",
                    err
                );
                // Let's recreate the DB. Ignoring any cleaning up errors. The last step let's report an error
                let _ = std::fs::remove_dir_all(&db_path);
                let _ = create_dir_all(&db_path);
                Store::new(db_path.to_str().unwrap(), None, Some(DB_DIR), None)?
            }
        };

        let res = Backend { db: store };
        Ok(res)
    }
}

impl AddressBookBackend for Backend {
    fn get_contact(&mut self, name: &[u8]) -> Result<Contact, Error> {
        let contact_key = to_key(CONTACT_PREFIX, &mut name.to_vec());
        option_to_not_found(self.db.get_ser(&contact_key, None), || {
            format!("Contact id: {:x?}", name.to_vec())
        })
        .map_err(|e| e.into())
    }

    fn contacts(&self) -> Box<dyn Iterator<Item = Contact>> {
        let protocol_version = self.db.protocol_version();
        let prefix_iter = self.db.iter(&[CONTACT_PREFIX], move |_, mut v| {
            ser::deserialize(
                &mut v,
                protocol_version,
                ser::DeserializationMode::default(),
            )
            .map_err(From::from)
        });
        let iter = prefix_iter.expect("deserialize").into_iter();
        Box::new(iter)
    }

    fn batch<'a>(&'a self) -> Result<Box<dyn AddressBookBatch + 'a>, Error> {
        let batch = self.db.batch()?;
        let batch = Batch {
            _store: self,
            db: RefCell::new(Some(batch)),
        };
        Ok(Box::new(batch))
    }
}

pub struct Batch<'a> {
    _store: &'a Backend,
    db: RefCell<Option<grin_store::Batch<'a>>>,
}

impl<'a> AddressBookBatch for Batch<'a> {
    fn save_contact(&mut self, contact: &Contact) -> Result<(), Error> {
        let mut key = contact.get_name().to_string().into_bytes();
        let contact_key = to_key(CONTACT_PREFIX, &mut key);
        self.db
            .borrow()
            .as_ref()
            .unwrap()
            .put_ser(&contact_key, contact)?;
        Ok(())
    }

    fn delete_contact(&mut self, name: &[u8]) -> Result<(), Error> {
        let ctx_key = to_key(CONTACT_PREFIX, &mut name.to_vec());
        self.db
            .borrow()
            .as_ref()
            .unwrap()
            .delete(&ctx_key)
            .map_err(|e| e.into())
    }

    fn commit(&mut self) -> Result<(), Error> {
        let db = self.db.replace(None);
        db.unwrap().commit()?;
        Ok(())
    }
}

impl ser::Writeable for Contact {
    fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), CoreError> {
        let json = json!({
            "name": self.get_name(),
            "address": self.get_address().to_string(),
        });
        writer.write_bytes(&json.to_string().as_bytes())
    }
}

impl ser::Readable for Contact {
    fn read<R: ser::Reader>(reader: &mut R) -> Result<Contact, CoreError> {
        let data = reader.read_bytes_len_prefix()?;
        let data = std::str::from_utf8(&data).map_err(|e| {
            CoreError::CorruptedData(format!("Unable to read contacts data, {}", e))
        })?;

        let json: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
            CoreError::CorruptedData(format!("Unable to read contacts data, {}", e))
        })?;

        let address = <dyn Address>::parse(json["address"].as_str().unwrap()).map_err(|_| {
            CoreError::CorruptedData(
                "Unable to read contacts data, Not found 'address'".to_string(),
            )
        })?;

        let contact = Contact::new(json["name"].as_str().unwrap(), address).map_err(|_| {
            CoreError::CorruptedData("Unable to read contacts data, Not found 'name'".to_string())
        })?;

        Ok(contact)
    }
}
