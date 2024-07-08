# Insecure application example

To login go to /login  
To register go to /register  
Admin panel is at /admin  
Index page (only for logged in users) is at /  

You can view/manipulate cookies in the browser tools on the Application tab

This application has a number of easy to make vulnerabilities:
* Users are authenticated using a cookie with just an easily guessable user id.
* The admin panel exposes secret information to anyone logged in as admin, maybe even admins shouldn't be able to access that information
* Even though the link to the admin panel is removed when the logged in user is not an admin, the admin panel itself is still accessible to anyone logged in and knowledgeable of the url
* When registering a new user, any existing user with the same username has its password overwritten
* The username and secret shown on the admin panel and the home page are vulnerable to HTML and JS injection
