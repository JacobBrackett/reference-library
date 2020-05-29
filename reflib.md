The Reference Library is a documentation library for developers that outlines the basic security requirements and common cases of features related to 3rd party systems, application entry points, and project functionality. 

# Summary 
* [Third Party Systems](#Third-Party-Systems)
    * [Third Party JavaScript](#Third-Party-JavaScript)
    * [Third Party APIs](#Third-Party-APIs)
    * [Cloud Security ](#Cloud-Security)
* [Application Entry Points](#Application-Entry-Points)
    * [URL Routes](#URL-Routes)
    * [GraphQL](#GraphQL-Queries-or-Mutations)
* [Project Functionality](#Project-Functionality)
    * [File Uploads](#File-Uploads)
    * [XML](#XML-Data-Parsing-or-Generation)
    * [HTML/Markdown](#User-Supplied-HTML-or-Markdown)
    * [Session Management](#Session-Management)
    * [Billing](#Billing)
    * [Registration](#Registration)
    * [Authentication](#Authentication)
    * [Auth Tokens](#Authentication-Tokens)
    * [Encryption](#Encryption)
    * [Hashing](#Hashing)
* [Language Specific Resources](#Language-Specific-Resources)
* [Security Resources](#Security-Resources)
* [Submit Feedback](https://forms.gle/DUJatsudxUJbmz5W7)

# Third Party Systems
## Third Party JavaScript
Third Party JavaScript are scripts that can be embedded into any site directly for a third party vendor. These scripts can include ads, analytics, widgets, and other scripts that make the web more dynamic and interactive. Since these scripts are created and/or hosted by a third party, the third party can be compromised and affect the site with the embedded JavaScript. Risks include loss of control over changes to the client application, execution of arbitrary code on client systems, and the disclosure or leakage of sensitive information. 

### Best Practices

Review the JavaScript
* Validate and sanitize user input
* Avoid document.write()
* Avoid scripts that pollute the global scope
* Keep JavaScript libraries updated

Beyond reviewing the JavaScript code for vulnerabilities, there are multiple ways to securely implement Third Party JavaScript

1. Self Host Third Party JavaScript

    Instead of using JavaScript that is hosted by a third party, one can self host the JavaScript and review the code. Updates to the script would need to be manually changed and features may be limited. 

    Example:
    ```selfhost
    <img src="http://example.com/tracking?data=DATA" width="0" height="0">
    ```

2. Sandboxing with iFrame

    Third party scripts can be loaded directly into an iframe from a different domain. It will work as a "jail" and vendor JavaScript will not have direct access to the host page DOM and cookies. The host main page and sandbox iframe can communicate between each other via the postMessage mechanism. An iframe from a different origin with the sandbox attribute will be restricted from accessing information on the main page and has certain features restricted. 

    Example: 
    ```sandbox
    <iframe sandbox="allow-scripts allow-same-origin" src="//js.onemedical.io/external"> 
    ```

3. Tag Manager

    An indirect request to the vendor can be made through a tag manager. A few lines of code on the host page will request a javascript file or url from a tag manager site, not from the javascript vendor site. The tag manager site returns the third party javascript files that the host company has configured to be returned. The content returned by the tag manager can be dynamically changed by a host site employee, such as a member of the marketing team. 

    The tag manager can be vulnerable because the tag manager interface can be used to generate code to get unvalidated data from the DOM (e.g. URL parameters) and store it in some page location that would execute javascript. 

    If using a tag manager, limit DOM data to the host defined data layer. The data layer should either be (1) a DIV object with attribute values that have the marketing or user behavior data that the 3rd party wants or (2) a set of JSON objects with the same data. Each variable or attribute contains the value of some DOM elements or the description of a user action. The data layer is the complete set of values that all vendors need for that page. The data layer is created by the host developers.

    Javascript files can be changed on the vendor site and any call from the browser will get the changed JavaScript. One way to manage this risk is with the subresource integrity, which will ensure that only the code that has been reviewed is executed. The developer generates integrity metadata for the vendor javascript, and adds it to the script element.

    Example: 
    ```subresource
    <script src="https://analytics.vendor.com/v1.1/script.js"
    integrity="sha384-MBO5IDfYaE6c6Aao94oZrIOiC7CGiSNE64QUbHNPhzk8Xhm0djE6QqTpL0HzTUxk"
    crossorigin="anonymous">
    </script>
    ```

### References
* [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
* [Loading Third Party JavaScript](https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/loading-third-party-javascript)

[Back](#summary)

## Third Party APIs
Third Party APIs are APIs provided by third parties and located on third party servers to allow you to access their functionality. Third party APIs can be classified into two types of applications: public application and confidential application. 

### Public Applications
Public applications cannot hold credentials securely.

Public clients are incapable of maintaining the confidentiality of their credentials. Sensitive information should not be transmitted. 

### Confidential Applications
Confidential applications require authentication to access the API and potentially contain sensitive information. 

1. Sensitive Information

    Sensitive Information should not appear in the URL, as this can be captured in the web server logs, which makes them easily exploitable. Examples include:
    * Usernames
    * Passwords
    * Session Tokens
    * API Keys
    * Account Numbers
    * Credit Card Numbers

    The example below shows this bad practice and exposes the API key. 
    ```badurl
    https://api.domain.com/user-management/users/{id}/someAction?apiKey=abcd123456789
    ```

2. SSL/TLS

    APIs should use SSL/TLS properly to prevent man-in-the-middle (mitm) attacks, in which an attacker sits between the API and an application/user by intercepting the traffic between the two and impersonates each to the other. 

3. IP Whitelisting 

    Use IP Whitelisting when possible. 

### Slack API Best Practices

Specific information on the Slack API, Methods, and Scopes can be found [here](https://sites.google.com/a/onemedical.com/one-medical-wiki/all-homepages/security-homepage/slack-app-development)

### References
* [REST API Security Essential](https://restfulapi.net/security-essentials/)
* [Types of Applications](https://auth0.com/docs/applications/concepts/app-types-confidential-public)

[Back](#summary)

## Cloud Security

### Best Practices
* Shared cloud security responsibilities
* Data encryption in the cloud
* Establishing cloud data deletion policies
* Managing access control

[Cloud Security at One Medical](https://docs.google.com/document/d/1KXo6DiZUSS8mpgBF7aK-I3Je4uHeBco5igaTqF_pTxE/edit#heading=h.tyzt5jdjti9t)

### References
* [Cloud Security Best Practices](https://solutionsreview.com/cloud-platforms/7-cloud-security-best-practices-to-keep-your-cloud-environment-secure/)

[Back](#summary)

# Application Entry Points
## URL Routes & Query Parameters

URL Routes allows the developer to configure an application to accept request URLs that do not map to physical files. Routing enables us to define URL patterns that map to the request handler, allowing the user to navigate through different application views on a single page. 

URL Query Parameters are a defined set of parameters attached to the end of a url. They are extensions of the URL that are used to help define specific content or actions based on the data being passed. 

A vulnerable URL and its parameters is an entry point where an attacker can start an attack. Attacks can range from learning sensitive information to modifying application behavior. 

### Best Practices

1. Sensitive Information in URL 

   * Information that appears in the URL should not be considered protected even if the application is transmitting data over HTTPS. URL parameters can be exposed in many places including referrer fields, server/proxy logs as well as browser history. 
    * Anything considered sensitive should always remain in the body of the request, not the URL.
    * Look for any requests that are making GET instead of POST and review the parameters that are being used
    * Consult server logs looking for sensitive data such as passwords or keys

2. Default Error Messages

    Error message information disclosure occurs when improperly handled error messages reveal sensitive information about underlying applications or infrastructure. Error messages should only contain minimal details that are useful to the intended audience, and nobody else.

3. Sanitize User Input

    Sanitize input by stripping all but known-safe tags and attributes. 
    
    An attacker can sneak malicious JavaScript into the URL, which is then executed. An attacker can also pass malicious input to the file include commands to access unauthorized or sensitive files available on the web server

    * Ruby: The sanitize-url gem provide a single method sanitize_url, which accepts a URL and returns one with JavaScript removed. 

        Ruby gem sanitize-url
        ```
        sanitize_url('http://example.com', :schemes => ['http', 'https'])
        ```
        
        If sanitize_url receives a URL with a forbidden scheme, it wipes out the entire URL and returns a blank string. You can override this behavior and have it return a string of your choosing like this:
        ```
        sanitize_url('javascript:alert("XSS")', :replace_evil_with => 'my replacement')
        # => 'my replacement'
        ```
    
    * Angular: [DomSanitizer](https://angular.io/api/platform-browser/DomSanitizer) sanitizes values to be safe to use in different DOM contexts. 
    
    * Angular: [Validators](https://angular.io/api/forms/Validators) can be used to validate data. 

4. Access Control 

    Resources should be behind authentication to prevent unauthorized access
    
    Use route guards to prevent users from navigating to parts of an app without authorization. The following route guards are available in Angular:
    * CanActivate
    * CanActivateChild
    * CanDeactivate
    * Resolve
    * CanLoad
    
5. URL Redirection

    Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. 
    
    When we want to redirect a user automatically to another page, the Rails method redirect_to can be used
    ```Rails
    redirect_to login_path
    ```
    
6. HTTPS
    
    Only allow HTTP(S) protocols. All other protocols, including JavaScript URIs such as javascript:alert(1) should be blocked

### Anti-Patterns
* Input starting with a / to redirect to local pages is not safe. //example.org is a valid URL.
* Input starting with the desired domain name is not safe. https://example.org.attacker.com is valid.
* Data URIs such as data:text/html,<script>alert(document.domain)</script> should be blocked
* URIs containing CRLF characters can lead to header injection or response splitting attacks, and should be blocked.

### References 

* [Sanitize in Ruby on Rails](https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html)
* [sanitize-url in ruby](https://www.rubydoc.info/gems/sanitize-url)
* [File Inclusion](https://resources.infosecinstitute.com/file-inclusion-attacks/#gref)
* [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

[Back](#summary)

## GraphQL Queries or Mutations
GraphQL is a data query language that makes it easier to get data from a server to a client via an API call. It isn’t tied to any specific database or storage engine and is instead backed by existing code. GraphQL endpoints are vulnerable similar to most query languages and can also be vulnerable to SQL injection. 

### Best Practices
1. Query Whitelisting

    One of the best practices of GraphQL is to write static strings using the GraphQL language. It better to avoid generating queries dynamically at runtime and it's better to use the GraphQL query language directly than say, through javascript syntax (like tagged template literals) because the best GraphQL tools and integrations rely on the static query language.

    Maintaining that list of approved queries manually would obviously be a pain, but  the Apollo team created persistgraphql, which automatically extracts all queries from your client-side code and generates a nice JSON file out of it.

    ```
    app.use('/api', graphqlServer((req, res) => {
      const query = req.query.query || req.body.query;
      // TODO: Get whitelist somehow
      if (!whitelist[query]) {
        throw new Error('Query is not in whitelist.');
      }
      /* ... */
    }));
    ```

2. Rate Limiting 

    A GraphQL query can take arbitrarily many actions compared to a REST API in which each HTTP request performs exactly one action. Simply limiting the number of HTTP requests received is not an adequate protection for a GraphQL API. Attackers can submit expensive, nested queries that overload your server, databases, and network, denying your web service to other applications.

    There are generally two strategies to defend against a denial of service attack caused by a complex query: 
    * Depth Limiting 
        Query depth can be limited so that maliciously deep queries are blocked before the result is computed 
        
        [GraphQL Depth Limit](https://github.com/stems/graphql-depth-limit) is a popular module that limits the depth of all queries. 
        
        This solution, however, ignores the possibility of an expensive query that doesn’t require a large depth.
        
        Limiting query depth with express-graphql and graphql-depth-limit is done using validationRules as follows:
        ```
        import depthLimit from 'graphql-depth-limit'
        import express from 'express'
        import graphqlHTTP from 'express-graphql'
        import schema from './schema'

        const app = express()

        const DepthLimitRule = depthLimit(
          4,
          { ignore: [ 'whatever', 'trusted' ] },
          depths => console.log(depths)
        )

        const graphqlMiddleware = graphqlHTTP({
          schema,
          validationRules: [
            DepthLimitRule,
          ],
        })

        app.use('/graphql', graphqlHTTP((req, res) => ({
          graphqlMiddleware
        })))
        ```
        
    * Limiting Query Complexity

        * Complexity Score System
        
        Complexity score system addresses the concern of an expensive query with a small depth. In a complexity scoring system, each portion of a query is assigned a complexity score, and any request with a total complexity greater than a chosen maximum value would be rejected.
        
        Query complexity can be limited with graphql-validation-complexity and express-graphqlis
        
        * Limiting Query by Cost

        Cost should be assigned to each query and maximum cost per query should be specified. 
        
        graphql-cost-analysis makes calculating query costs somewhat easier but allowing custom fine-grained control over specific fields with the @cost directive.

3. User Input

    Input should be inferred from the user's session. 

    Bad Example
    ```
    function updateUser({ id, email }) {
      return User.findOneAndUpdate({ _id: id }, { email })
      .catch(error => {
        throw error;
      });
    }
    ```

    Good Example
    ```
    function updateUser({ email }, context) {
      return User.findOneAndUpdate({ _id: context.user._id }, { email })
      .catch(error => {
        throw error;
      });
    }
    ```

4. Disable Introspection

    Introspection is enabled by default and should be **disabled** in staging and production. Introspection allows anybody can get a full description of your schema by sending a special query containing meta fields type and schema and makes discovery of hidden endpoints trivially easy. 

5. Use parameterized queries

    Even though GraphQL is strongly typed, SQL/NoSQL Injections are still possible since GraphQL is just a layer between client apps and the database. The application might not throw an error, but can still be vulnerable to blind, time-based or even out-of-band SQL injection attacks.

    GraphQL SQL Injection Example: 
    ```
    mutation search($filters Filters!){
        authors(filter: $filters)
        viewer{
            id
            email
            firstName
            lastName
        } 
    }

    {
        "filters":{
            "username":"paolo' or 1=1--"
            "minstories":0
        }
    }
    ```

### References
* [GraphQL API Security](https://leapgraph.com/graphql-api-security)
* [Apollo Securing GraphQL API](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
* [Protecting your GraphQL API](https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4)

[Back](#summary)

# Project Functionality
## File Uploads
File Uploads allow a user to upload a file, usually of a specific type. Unrestricted file uploads can lead to many consequences, ranging from defacement to complete system takeover. 

### Best Practices

1. Whitelist File Extensions
    
    Put a whitelist in place to limit what types of files can be uploaded to the system using server side checks

2. Limit file uploads to a certain size to prevent exhaustion of resources

3. Validate "Content-Type" Header 

4. Sanitize filename and extensions

    All the control characters and Unicode ones should be removed from the filenames and their extensions without any exception. Also, the special characters such as “;”, “:”, “>”, “<”, “/” ,”\”, additional “.”, “*”, “%”, “$”, and so on should be discarded as well. If it is applicable and there is no need to have Unicode characters, it is highly recommended to only accept Alpha-Numeric characters and only 1 dot as an input for the file name and the extension; in which the file name and also the extension should not be empty at all (regular expression: [a-zA-Z0-9]{1,200}\.[a-zA-Z0-9]{1,10}).

5. Limit filename length

6. Limit file size 

7. Limit File Directory Permissions

    Uploaded directory should not have any “execute” permission and all the script handlers should be removed from these directories.

### References
* [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [MITRE Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html)

[Back](#summary)

## XML Data Parsing or Generation
XML is a popular data format used in web services, documents, and image files. XML data is interpreted through an XML parse. 

An XML External Entity (XXE) attack is a type of attack that abuses XML parsers. A weakly configured XML parser processes XML input containing a reference to an external entity. Using XXE, an attacker is able to cause Denial of Service (DoS) as well as access local and remote content and services. XXE can be used to perform Server Side Request Forgery (SSRF) inducing the web application to make requests to other applications. In some cases, XXE may even enable port scanning and lead to remote code execution.

Example of an XXE attack
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///dev/random" >]>
<foo>&xxe;</foo>
```

### Best Practices
The safest way to protect XML parsers is to disable DTDs (external entities) completely. 
```
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

More specific information on language specific protections can be found [here](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

### References
* [OWASP XXE Vulnerabilities](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) 
* [What is XXE?](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/)

[Back](#summary)

## User Supplied HTML or Markdown

Applications read the markdown code then generates HTML. The code could include malicious JavaScript that is added to the web page when processed by the markdown processor, allowing an attacker to read user's cookies and even steal credentials. 

### Best Practices

1. Removing HTML entities from markdown does not prevent XSS. Markdown syntax can generate XSS attacks.

2. XSS filtering should be done **after** Showdown has processed any input, not before or during. If you filter before, it’ll break some of Markdown’s features and will leave security holes.

3. Perform the necessary filtering server-side, not client side. XSS filtering libraries are useful but shouldn't be used blindly.

### References
* [Exploiting XSS via Markdown](https://medium.com/taptuit/exploiting-xss-via-markdown-72a61e774bf8)
* [Mitigating Markdown's XSS Vulnerability](https://github.com/showdownjs/showdown/wiki/Markdown's-XSS-Vulnerability-(and-how-to-mitigate-it))
* [Markdown and XSS](https://michelf.ca/blog/2010/markdown-and-xss/)

[Back](#summary)

## Session Management 
A HTTP cookie is a small amount of data generated by a website and saved by your web browser. The purpose of a HTTP cookie is to remember information about the user and are sent in the HTTP headers. 

The session ID exchange mechanism based on cookies provides multiple security features in the form of cookie attributes that can be used to protect the exchange of the session ID.

### Cookie Best Practices 
1. Secure Attribute

    The secure flag should be set. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a the cookie in clear text.
    
2. HttpOnly Attribute

    In traditional web apps, HttpOnly flag is set so that cookies are not displayed through client-side scripts.

    The HttpOnly flag does not need to be set for One Medical web applications because JS needs to access the token to attach it to the header. They only use cookies for storage, not for actual authentication like traditional web apps.

3. SameSite Attribute 

    SameSite should be set as strict. When the SameSite attribute is set as strict, cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites. The SameSite cookie attribute protects against CSRF attacks since your cookies are not sent with the request initiated by third parties. 
    
4. "Path" Attribute

    Path attribute should be set as restrictive as possible to the web application path that makes use of the session ID. The Path attribute indicates a URL path that must exist in the requested URL in order to send the Cookie header. 

5. "Domain" Attribute

    The Domain attribute should not be set so the cookie is restricted to the origin server. The Domain attribute specifies which hosts are allowed to receive the cookie. If unspecified, it defaults to the host of the current document location, excluding subdomains. 

6. Cookie Lifetime

    The Lifetime of a cookie can be defined in two ways: 
    * Session cookies are deleted when the current session ends. The browser defines when the "current session" ends, and some browsers use session restoring when restarting, which can cause session cookies to last indefinitely long.
    * Permanent cookies are deleted at a date specified by the Expires attribute, or after a period of time specified by the Max-Age attribute.

### References
* [OWASP Cookie](https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20171130_Cookie_Security_Myths_Misconceptions_David_Johansson.pdf)
* [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[Back](#summary)

## Billing 
Billing includes processing credit card payments, refunds, and discount codes. While best practices are integrated into the PCI Data Security Standard, many vulnerabilities still exist within the billing process. 

The scope of billing at One Medical is limited because customers cannot add or remove items for a "cart", inventory does not need to be checked, physical goods are not shipped. Additionally, One Medical utilizes the Stripe API to handle credit card processes. 

### Best Practices
1. Review [Stripe Documentation for Best practices on Fraud Prevention](https://stripe.com/docs/disputes/prevention)

2. Production Environment
    * Test data should not be used in production
    * Debug mode should not be enabled in production
    * Remove code from the production environment that is supposed to be only available in the testing environment. 

3. Parameter Manipulation 
    * Price Manipulation - The user should not be able to manipulate the price value on the callback from the payment server, which goes through the user's browser and not via the backend API.
    
    * Repeated Input Parameter - Different technologies may behave differently when they receive repetitive input parameters. This becomes especially important when the application sends server-side requests to other applications with different technologies, or when customized code to identify the inputs is in place.
        ```
        /page.extension?amount=2&amount=3&amount[]=4
        ```
        
    * Omitting an Input Parameter or its Value - The follow test cases should be tested for sensitive input to bypass certain protection mechanisms: 
        * Removing the value
        * Replacing the value by a null character
        * Removing the equals-sign character after the input parameter
        * Removing the input parameter completely from the request
            
    * Logical Flaws - The application behavior should be monitored while changing parameters to detect logical flaws. 
        * Sometimes web applications contain a parameter which shows the current page number or stage. A user may be able to bypass certain stages or pages by manipulating this parameter in the next request.
        * It is not normally recommended to change more than one parameter during a limited time frame of testing; however, some logical flaws can be found only by changing more than one parameter at a time. This is useful when an application detects parameter manipulation for parameters such as the price field. Although it may not be feasible to test different combinations of all input parameters, it is recommended to modify at least a couple of the interesting inputs at the same time. 
        
4. Replay attacks

    A replay attack occurs when all or part of a message between the client and the server are copied and replayed later. The parameters can also be changed when no parameter manipulation prevention technique such as message signature validation is present on the server side. Although a message can be signed or encrypted to prevent parameter manipulation, this will not stop replay of a message which was originally created by a trusted party.

    An application can be vulnerable to serious security issues when it trusts replayed requests without performing any further validation to check whether they have already been received or sent in the right order.

5. Card number related issues

    If card numbers need to be presented to the user, card numbers should only be partially displayed (e.g. the last for digits) when necessary. The pages which contain the card numbers should be password protected

6. Discount codes

    The application policy should be reviewed whenever dynamic prices are found, to ensure that the changed prices are within the allowed margin. In addition, a secure cryptographic method should be used when the prices are generated by a trusted party or even by the website itself, in order to identify any manipulation by untrusted parties.

    Discount codes and vouchers which can be used to reduce the final price should be tested to ensure they are not predictable and cannot be easily enumerated.

    The application behavior after applying any discount method should be reviewed to see if there are any interesting parameters that can be manipulated or replayed to use a discount code for different products, after a certain date when it is expired, or multiple times when it should expire after the first use (concurrency issues can also be tested here).

7. Hidden/Insecure Backend APIs

    Backend APIs which are used by electronic point of sale systems or payment servers are often old and insecure, as they are not directly accessible to the users. Sometimes even mobile or tablet application APIs are also insecure, as the developer did not think about security in the server side application layer when implementing them.

    Some of these APIs and web services do not have any protection against many of the described attack techniques, and some of them even suffer from access control issues, allowing an attacker to perform administrative tasks such as balance adjustment.

### What does Stripe do for [Security](https://stripe.com/docs/security/stripe)? 
* HTTPS and HSTS for secure connections
* Encryption of sensitive data and communication
* PGP Encryption
* Vulnerability Disclosure & Reward Program 

### References
* [Security at Stripe](https://stripe.com/docs/security/stripe)
* [Common Security Issues in Financially-Oriented Web Applications](https://www.nccgroup.com/uk/our-research/common-security-issues-in-financially-orientated-web-applications/)

[Back](#summary)

## Registration
Every user that signs up for the application needs to be properly verified, adequately authenticated, and be given a safe and user-friendly path to recovery.

### Best Practices

1. Verify new users
    * Always send the verification link before activating the account. 
    * Never allow duplicate registrations for the same email address/username/mobile.

2. Input Validation
    * No empty or null fields
    * Email address is valid 
        The best way to validate email addresses is to perform some basic initial validation, and then pass the address to the mail server and catch the exception if it rejects it.

        The initial validation could be as simple as:
        * The email address contains two parts, separated with an @ symbol.
        * The email address does not contain dangerous characters (such as backticks, single or double quotes, or null bytes).
                * Exactly which characters are dangerous will depend on how the address is going to be used (echoed in page, inserted into database, etc).
        * The domain part contains only letters, numbers, hyphens (-) and periods (.).
        * The email address is a reasonable length:
            * The local part (before the @) should be no more than 63 characters.
            * The total length should be no more than 254 characters.
    * Password confirmation field matches the password field
    
3. Recover Access to Account

    Recovery should not delve too much information.  

4. Business Logic Flaws

    Business logic should be reviewed for flaws. Additionally, if there are multiple registration flows, logic should be consistent across all flows. 

5. Password Requirements 
    * At the very minimum, there should be a 8-character minimum length (dependent on context)

An example of [secure registration flow](https://www.technolush.com/blog/secure-registration-flow)

### References
* [Email Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#email-address-validation)
* [Verification Attacks](https://twitter.com/HackerHumble/status/1249648868846796801)
* [User Account Best Practices](https://cloud.google.com/blog/products/gcp/12-best-practices-for-user-account)
* [Account Security Best Practices](https://pages.twilio.com/rs/294-TKB-300/images/Account_Security_Best_Practices.pdf)
* [NIST Password Standards](https://specopssoft.com/blog/nist-password-standards/)

[Back](#summary)

## Authentication

### Best Practices 

1. Hash passwords

    Do not store plaintext passwords under any circumstances. Instead, a cryptographically strong hash of the password that cannot be reversed should be stored. Strong hashing algorithms include: PBKDF2, Argon2, Scrypt, or Bcrypt. The hash should be salted with a value unique to that specific login credential. Do not use deprecated hashing technologies such as MD5, SHA1 and under no circumstances should you use reversible encryption or try to invent your own hashing algorithm.

2. Separate concept of user identity and user account
    
    Users should not be identified by a single form of identity, such as email address, phone number, or unique ID provided by an OAUTH response. A well designed user management system has low coupling and high cohesion between different parts of a user's profile. It may be helpful to have an internal global identifier for every user and link their profile and authentication identity via that ID as opposed to piling it all in a single record.

3. Make a conscious decision on session length

    There should be thresholds after which you ask for password, 2nd factor or other user verification.
    
    Consider how long a user should be able to be inactive before re-authenticating. Verify user identity in all active sessions if someone performs a password reset. Prompt for authentication or 2nd factor if a user changes core aspects of their profile or when they're performing a sensitive action. Consider whether it makes sense to disallow logging in from more than one device or location at a time.

    When your service does expire a user session or require re-authentication, prompt the user in real-time or provide a mechanism to preserve any activity they have unsaved since they were last authenticated. It's very frustrating for a user to fill out a long form, submit it some time later and find out all their input has been lost and they must log in again.

4. 2-Step Verification

    Consider the practical impact on a user of having their account stolen when choosing from 2-Step Verification (also known as two-factor authentication or just 2FA) methods. SMS 2FA auth has been deprecated by NIST due to multiple weaknesses, however, it may be the most secure option your users will accept for what they consider a trivial service. Offer the most secure 2FA auth you reasonably can. Enabling third-party identity providers and piggybacking on their 2FA is a simple means to boost your security without great expense or effort.

5. Turn off autocomplete

    The autocomplete feature can become a liability once attackers gain access to a victim's computer or the browser. For example, if an attacker uses the browser of a victim, they’ll also be able to log in to the victim's account easily because the autocomplete feature will fill in the victim's email address and password credentials.
    
    Autocomplete can be turned off with the autocomplete flag
    ```
    <input type="text" name="email_address" autocomplete="off" />
    ```

6. SSL/TLS

    SSL/TLS should be properly implemented to prevent man-in-the-middle (mitm) attacks, in which an attacker sits between the client and the server  by intercepting the traffic between the two and impersonates each to the other. 
    
7.  CSRF 

    CSRF vulnerabilities can occur on login forms where the user is not authenticated. In a login CSRF attack, the attacker forges a login request to a site using the attacker's user name and password. If the site is vulnerable to login CSRF, the user is logged into the site as the attacker because the server responds with a Set-Cookie header that instructs the browser to mutate its state by storing a session cookie. This session cookie is used to bind subsequent requests to the user’s session and hence to the attacker’s authentication credentials. Login CSRF attacks can have serious consequences, depending on other site behavior:

    Login CSRF can be mitigated by creating pre-sessions (sessions before a user is authenticated) and including tokens in login form. Pre-sessions cannot be transitioned to real sessions once the user is authenticated - the session should be destroyed and a new one should be made to avoid session fixation attacks

### References
* [12 Best Practices for User Account](https://cloud.google.com/blog/products/gcp/12-best-practices-for-user-account)
* [User Authentication Best Practices Checklist](https://techblog.bozho.net/user-authentication-best-practices-checklist/)

[Back](#summary)

## Authentication Tokens

### Best Practices

1. Keep tokens secret and safe

    The signing key should be treated like any other credential and revealed only to services that need it.
    
2. Do not add sensitive data to the payload

    Tokens are signed to protect against manipulation and are easily decoded. Add the bare minimum number of claims to the payload for best performance and security.
    
3. Give tokens an expiration 

    Technically, once a token is signed, it is valid forever—unless the signing key is changed or expiration explicitly set. This could pose potential issues so have a strategy for expiring and/or revoking tokens.
    
    SSO request/response pairs should be valid for a short window, and only usable one time, for one SP.
    
4. HTTPS

    Do not send tokens over non-HTTPS connections as those requests can be intercepted and tokens compromised.
    
5.  Consider all authorization use cases

    Adding a secondary token verification system that ensures tokens were generated from your server, for example, may not be common practice, but may be necessary to meet your requirements.

6. Validate tokens before using any of their data in application logic.

7. Verify random values are not hardcoded

    During testing, hardcoded values may be used. It is important to verify that the cryptographically secure strings are randomly generated. 

    The example below shows that the codeVerifier is set to a hardcoded string "codechallenge", defeating the purpose of a cryptographically secure token. 
    ```
    verifyAccessToken(code: string): Observable<string | boolean> {
    const accessTokenRequestParams: AccessTokenRequestParams = {
      code,
      clientId: this.oauth2.clientId,
      grantType: ‘authorization_code’,
      redirectUri: this.window.location.origin,
      codeVerifier: ‘codechallenge’,
    };
    ```

8. When possible, pass tokens in POST body, instead of as GET query parameters.
    
9. In SPA web clients, avoid storing tokens where malicious JS can access it, such as local/session storage.

More information on token security guidelines can be found [here](https://docs.google.com/document/d/1GeCqFgjb-vV-6uBxlZaH_clZc6m72fBgYz-jANfhIz4/edit)
    
### References
* [Token Best Practices](https://auth0.com/docs/best-practices/token-best-practices)

[Back](#summary)

## Encryption
Encryption should only be used in edge cases where it is necessary to be able to obtain the original password. The ability to decrypt passwords represents a serious security risk, so it should be fully risk assessed. Where possible, an alternative architecture should be used to avoid the need to store passwords in an encrypted form.

### Best Practices
* Minimize the storage of sensitive information
    The best way to protect sensitive information is not store it in the first place. Wherever possible, the storage of sensitive information should be avoided. 
* Use strong cryptography and keys
    * For symmetric encryption, AES with a key that's at least 128 bits (ideally 256 bits) and a secure mode should be used as the preferred algorithm 
    * For asymmetric encryption, use elliptical curve cryptography (ECC) with a secure surve such as Curve25519 as a preferred algorithm.  If ECC is not available and RSA must be used, then ensure that the key is at least 2048 bits.
* Proper key management
    Formal processes should be implemented and tested to cover all aspects of key management: 
    * Generating and storing new random keys
    * Distributing keys to the required parties
    * Deploying keys to application servers
    * Rotating and decommissioning old keys

### Anti-Patterns
* Avoid using custom algorithms 
    * Use only public, vetted cryptography and security protocols. 
* Avoid using Master passwords
    * Widely shared "secrets" can be revealed if the master password is leaked or someone reverse-engineers a unit. 
* Avoid using the same key in both directions for communications

### References
* [Encryption Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [Encryption Security Pitfalls](https://users.ece.cmu.edu/~koopman/lectures/ece642/41_securitypitfalls.pdf)
* [More Pitfalls](https://www.bankinfosecurity.com/encryption-avoiding-pitfalls-that-lead-to-breaches-a-11918)

[Back](#summary)

# Language Specific Resources

* [Rails Security Practices](https://guides.rubyonrails.org/v3.1.1/security.html)
    * [Ruby on Rails OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheatsheet.html)
* [Angular Security Practices](https://angular.io/guide/security)
* [ElasticSearch Security Practices](https://www.elastic.co/guide/en/elasticsearch/reference/current/elasticsearch-security.html)

[Back](#summary)

# Security Resources
* [Security Help Center](https://securityonemedical.zendesk.com/)
* Security Team DL: security@onemedical.com, appsec@onemedical.com
* OWASP

    The Open Web Application Security Project, or OWASP, is a non-profit organization dedicated to web application security. 

    * [OWASP Top 10](https://owasp.org/www-project-top-ten/)
    
        The OWASP Top 10 represents most critical security risks to web application. 
    
    * [OWASP Cheatsheet Series](https://cheatsheetseries.owasp.org/)
    
        The OWASP Cheatsheet Series provides in-depth information on specific application security topics. 

[Back](#summary)

# Feedback

[Submit Feedback](https://forms.gle/DUJatsudxUJbmz5W7)

[Back](#summary)

