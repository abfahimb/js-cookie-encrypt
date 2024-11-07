# Encrypt-cookiejs (Protected by Secret Key)

**Encrypt-cookiejs**  encrypt-storejs is a lightweight JavaScript package designed to securely manage data in browser cookies using advanced encryption techniques. This package ensures that sensitive data stored in cookies is encrypted, providing a higher level of security for client-side storage. It allows for flexible and customizable cookie management with support for various cookie attributes such as path, domain, expires, sameSite, and secure.


## Key Features

- **Data Encryption**  
  Automatically encrypts data before storing it in cookies, ensuring sensitive information remains secure and private. The encryption is performed using a configurable private key and salt.

- **Customizable Cookie Options**  
  Provides support for all standard cookie attributes, including `path`, `expires`, `secure`, `sameSite`, and `httpOnly`, allowing for fine-grained control over cookie behavior and security.

- **Nested Path Support**  
  Store and retrieve data from deeply nested object paths within cookies, offering flexibility when working with complex data structures.

- **Merge Data**  
  Supports merging new data with existing cookie data, allowing for incremental updates without overwriting the entire cookie. Ideal for scenarios requiring partial updates.

- **Cookie Expiration Management**  
  Easily extend the expiration of cookies, enabling the refresh of session data and control over the lifespan of cookies.

- **Cross-Domain Cookie Management**  
  Facilitates managing cookies across different domains, making it easier to store shared data across subdomains or different parts of your web application.

- **Clear All Cookies**  
  Includes a utility to clear all cookies for a specific domain or path, allowing privacy control and the ability to easily delete all stored cookies.

- **Secure by Default**  
  The package encrypts all stored data unless otherwise specified, ensuring that sensitive information is never stored in plain text.
