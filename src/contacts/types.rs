use std::fmt::{self, Debug, Display};

use common::{ErrorKind, Error};

pub const DEFAULT_MWCMQS_DOMAIN: &str = "mqs.mwc.mw";

pub const DEFAULT_MWCMQS_PORT: u16 = 443;

#[cfg(not(windows))]
pub const DEFAULT_GRINBOX_PORT: u16 = 443;
#[cfg(windows)]
pub const DEFAULT_GRINBOX_PORT: u16 = 80;
use grin_wallet_impls:: Address;

pub trait AddressBookBackend {
    fn get_contact(&mut self, name: &[u8]) -> Result<Contact, Error>;
    fn contacts(&self) -> Box<dyn Iterator<Item = Contact>>;
    fn batch<'a>(&'a self) -> Result<Box<dyn AddressBookBatch + 'a>, Error>;
}

pub trait AddressBookBatch {
    fn save_contact(&mut self, contact: &Contact) -> Result<(), Error>;
    fn delete_contact(&mut self, public_key: &[u8]) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
}

pub struct AddressBook {
    backend: Box<dyn AddressBookBackend + Send>,
}

impl AddressBook {
    pub fn new(backend: Box<dyn AddressBookBackend + Send>) -> Result<Self, Error> {
        let address_book = Self { backend };
        Ok(address_book)
    }

    pub fn add_contact(&mut self, contact: &Contact) -> Result<(), Error> {
        let result = self.get_contact(&contact.name);
        if result.is_ok() {
            return Err(ErrorKind::ContactAlreadyExists(contact.name.clone()))?;
        }
        let mut batch = self.backend.batch()?;
        batch.save_contact(contact)?;
        batch.commit()?;
        Ok(())
    }

    pub fn remove_contact(&mut self, name: &str) -> Result<(), Error> {
        let mut batch = self.backend.batch()?;
        batch.delete_contact(name.as_bytes())?;
        batch.commit()?;
        Ok(())
    }

    pub fn get_contact(&mut self, name: &str) -> Result<Contact, Error> {
        let contact = self.backend.get_contact(name.as_bytes())?;
        Ok(contact)
    }

    pub fn _get_contact_by_address(&mut self, address: &str) -> Result<Contact, Error> {
        for contact in self.contacts() {
            if contact.address == address {
                return Ok(contact);
            }
        }
        Err(ErrorKind::_ContactNotFound(address.to_string()))?
    }

    pub fn contacts(&self) -> Box<dyn Iterator<Item = Contact>> {
        self.backend.contacts()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    name: String,
    address: String,
}

impl Contact {
    pub fn new(name: &str, address: Box<dyn Address>) -> Result<Self, Error> {
        Ok(Self {
            name: name.to_string(),
            address: address.to_string(),
        })
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_address(&self) -> &String {
        &self.address
    }
}

impl Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.address.to_string())?;
        Ok(())
    }
}






