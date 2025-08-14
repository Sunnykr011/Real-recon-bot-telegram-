"""
Advanced Google Dorks Database for Vulnerability Discovery
Contains 200+ dorks categorized by vulnerability type
"""

class GoogleDorksDatabase:
    def __init__(self):
        self.dorks = self._initialize_dorks()
    
    def _initialize_dorks(self):
        """Initialize comprehensive Google dorks database"""
        return {
            "sql_injection": [
                'site:{domain} inurl:"id=" "Warning: mysql_fetch_array()"',
                'site:{domain} inurl:"id=" "Warning: mysql_num_rows()"',
                'site:{domain} inurl:"id=" "Warning: Cannot modify header information"',
                'site:{domain} inurl:"id=" "ORA-00933: SQL command not properly ended"',
                'site:{domain} inurl:"id=" "Microsoft OLE DB Provider for SQL Server"',
                'site:{domain} inurl:"id=" "Unclosed quotation mark"',
                'site:{domain} inurl:"id=" "ODBC Microsoft Access Driver"',
                'site:{domain} inurl:"page=" "mysql_fetch_array()"',
                'site:{domain} inurl:"page=" "ORA-01756"',
                'site:{domain} inurl:"page=" "Error Occurred While Processing Request"',
                'site:{domain} inurl:"id=" "SQL syntax" mysql',
                'site:{domain} inurl:"category=" "mysql_fetch_array"',
                'site:{domain} inurl:"category=" "Warning: mysql_num_rows()"',
                'site:{domain} inurl:"newsid=" "mysql error"',
                'site:{domain} inurl:"id=" "PostgreSQL query failed"',
                'site:{domain} inurl:"id=" "pg_exec() error"',
                'site:{domain} "SQL syntax" site:{domain}',
                'site:{domain} "mysql error" | "warning mysql"',
                'site:{domain} "PostgreSQL error" | "warning PostgreSQL"',
                'site:{domain} "ORA-" "Oracle error"',
            ],
            
            "xss_vulnerabilities": [
                'site:{domain} inurl:"search=" inurl:"q="',
                'site:{domain} inurl:"search.php?q="',
                'site:{domain} inurl:"search.asp?q="',
                'site:{domain} inurl:"search.jsp?q="',
                'site:{domain} inurl:"query=" OR inurl:"search="',
                'site:{domain} inurl:"keywords=" OR inurl:"keyword="',
                'site:{domain} inurl:"searchterm="',
                'site:{domain} inurl:"search" "reflected"',
                'site:{domain} inurl:"id=" intext:"<script>"',
                'site:{domain} inurl:"page=" intext:"alert"',
                'site:{domain} filetype:php inurl:"search="',
                'site:{domain} filetype:asp inurl:"search="',
                'site:{domain} filetype:jsp inurl:"search="',
                'site:{domain} inurl:"search.cfm?q="',
                'site:{domain} inurl:"/search/" intext:"query"',
                'site:{domain} "Search Results" inurl:"q=" OR inurl:"query="',
                'site:{domain} inurl:"find=" OR inurl:"lookup="',
                'site:{domain} intext:"powered by" inurl:"search="',
                'site:{domain} inurl:"?s=" OR inurl:"?search="',
                'site:{domain} inurl:"searchresults" OR inurl:"results"',
            ],
            
            "local_file_inclusion": [
                'site:{domain} inurl:"page=" inurl:".."',
                'site:{domain} inurl:"include=" inurl:".."',
                'site:{domain} inurl:"file=" inurl:".."',
                'site:{domain} inurl:"path=" inurl:".."',
                'site:{domain} inurl:"dir=" inurl:".."',
                'site:{domain} inurl:"load=" inurl:".."',
                'site:{domain} inurl:"read=" inurl:".."',
                'site:{domain} inurl:"get=" inurl:".."',
                'site:{domain} filetype:php inurl:"page="',
                'site:{domain} filetype:php inurl:"file="',
                'site:{domain} filetype:asp inurl:"include="',
                'site:{domain} filetype:jsp inurl:"include="',
                'site:{domain} inurl:"../../../../etc/passwd"',
                'site:{domain} inurl:"../../../etc/passwd"',
                'site:{domain} inurl:"../../etc/passwd"',
                'site:{domain} inurl:"etc/passwd" -inurl:"page="',
                'site:{domain} inurl:"/proc/version"',
                'site:{domain} inurl:"boot.ini"',
                'site:{domain} inurl:"include" filetype:php',
                'site:{domain} inurl:"require" filetype:php',
            ],
            
            "exposed_files": [
                'site:{domain} filetype:sql "INSERT INTO"',
                'site:{domain} filetype:sql "CREATE TABLE"',
                'site:{domain} filetype:log "password"',
                'site:{domain} filetype:bak "database"',
                'site:{domain} filetype:txt "username" "password"',
                'site:{domain} filetype:conf "password"',
                'site:{domain} filetype:config "password"',
                'site:{domain} filetype:ini "password"',
                'site:{domain} filetype:xml "password"',
                'site:{domain} filetype:env',
                'site:{domain} ".env" "DB_PASSWORD"',
                'site:{domain} filetype:backup',
                'site:{domain} ext:bak "database"',
                'site:{domain} ext:old "backup"',
                'site:{domain} filetype:dump',
                'site:{domain} "config.php" "password"',
                'site:{domain} "database.php" "password"',
                'site:{domain} "wp-config.php" backup',
                'site:{domain} filetype:csv "email" "password"',
                'site:{domain} ext:xls "password"',
            ],
            
            "admin_panels": [
                'site:{domain} inurl:admin',
                'site:{domain} inurl:administrator',
                'site:{domain} inurl:admin.php',
                'site:{domain} inurl:admin.html',
                'site:{domain} inurl:admin.asp',
                'site:{domain} inurl:admin.aspx',
                'site:{domain} inurl:admin.jsp',
                'site:{domain} inurl:"admin/login"',
                'site:{domain} inurl:"admin/index"',
                'site:{domain} inurl:cp inurl:admin',
                'site:{domain} inurl:controlpanel',
                'site:{domain} inurl:"control panel"',
                'site:{domain} inurl:adm',
                'site:{domain} inurl:"admin panel"',
                'site:{domain} inurl:"admin area"',
                'site:{domain} inurl:"admin section"',
                'site:{domain} inurl:"admin dashboard"',
                'site:{domain} inurl:cpanel',
                'site:{domain} inurl:"user management"',
                'site:{domain} intitle:"admin" inurl:login',
            ],
            
            "directory_listing": [
                'site:{domain} intitle:"Index of /"',
                'site:{domain} intitle:"Directory Listing"',
                'site:{domain} intitle:"Apache" "Index of"',
                'site:{domain} intitle:"nginx" "Index of"',
                'site:{domain} intitle:"IIS" "Index of"',
                'site:{domain} "Index of /" intext:"Parent Directory"',
                'site:{domain} "Directory Listing For" Apache',
                'site:{domain} intitle:"Index of /backup"',
                'site:{domain} intitle:"Index of /admin"',
                'site:{domain} intitle:"Index of /uploads"',
                'site:{domain} intitle:"Index of /files"',
                'site:{domain} intitle:"Index of /images"',
                'site:{domain} intitle:"Index of /config"',
                'site:{domain} intitle:"Index of /logs"',
                'site:{domain} intitle:"Index of /private"',
                'site:{domain} intitle:"Index of /tmp"',
                'site:{domain} intitle:"Index of /var"',
                'site:{domain} intitle:"Index of /www"',
                'site:{domain} "Apache Server at" "Port"',
                'site:{domain} "Lighttpd" intitle:"Index of"',
            ],
            
            "database_errors": [
                'site:{domain} "A Database Error Occurred"',
                'site:{domain} "Database Error" "Please try again"',
                'site:{domain} "Fatal error" "mysql"',
                'site:{domain} "Warning" "mysql_connect"',
                'site:{domain} "Error connecting" "database"',
                'site:{domain} "Connection failed" mysql',
                'site:{domain} "Can\'t connect to MySQL"',
                'site:{domain} "Access denied for user"',
                'site:{domain} "Unknown MySQL server host"',
                'site:{domain} "MySQL server has gone away"',
                'site:{domain} "Table doesn\'t exist"',
                'site:{domain} "Column count doesn\'t match"',
                'site:{domain} "Syntax error" SQL',
                'site:{domain} "Query failed" database',
                'site:{domain} "Connection timeout" mysql',
                'site:{domain} "Too many connections"',
                'site:{domain} "Lock wait timeout exceeded"',
                'site:{domain} "Deadlock found"',
                'site:{domain} "Duplicate entry" mysql',
                'site:{domain} "Data too long for column"',
            ],
            
            "login_pages": [
                'site:{domain} inurl:login',
                'site:{domain} inurl:"login.php"',
                'site:{domain} inurl:"login.html"',
                'site:{domain} inurl:"login.asp"',
                'site:{domain} inurl:"login.aspx"',
                'site:{domain} inurl:"login.jsp"',
                'site:{domain} intitle:login',
                'site:{domain} "User Login" OR "Member Login"',
                'site:{domain} "Sign In" intitle:login',
                'site:{domain} "Log In" intitle:login',
                'site:{domain} inurl:"user/login"',
                'site:{domain} inurl:"member/login"',
                'site:{domain} inurl:"auth/login"',
                'site:{domain} inurl:"account/login"',
                'site:{domain} inurl:"signin"',
                'site:{domain} inurl:"authenticate"',
                'site:{domain} "username" "password" login',
                'site:{domain} intext:"forgot password"',
                'site:{domain} "remember me" login',
                'site:{domain} "keep me logged in"',
            ],
            
            "api_endpoints": [
                'site:{domain} inurl:api',
                'site:{domain} inurl:"api/v1"',
                'site:{domain} inurl:"api/v2"',
                'site:{domain} inurl:"/rest/"',
                'site:{domain} inurl:"/graphql"',
                'site:{domain} filetype:json site:{domain}',
                'site:{domain} inurl:"swagger"',
                'site:{domain} "API Documentation"',
                'site:{domain} "REST API"',
                'site:{domain} inurl:"openapi"',
                'site:{domain} "postman" collection',
                'site:{domain} inurl:"/v1/api"',
                'site:{domain} inurl:"/api/docs"',
                'site:{domain} inurl:"/api-docs"',
                'site:{domain} filetype:wadl',
                'site:{domain} inurl:"wsdl"',
                'site:{domain} inurl:"/soap"',
                'site:{domain} "GraphQL" endpoint',
                'site:{domain} inurl:"/api/users"',
                'site:{domain} inurl:"/api/auth"',
            ],
            
            "sensitive_parameters": [
                'site:{domain} inurl:"debug=true"',
                'site:{domain} inurl:"test=1"',
                'site:{domain} inurl:"dev=1"',
                'site:{domain} inurl:"demo=true"',
                'site:{domain} inurl:"trace=1"',
                'site:{domain} inurl:"verbose=1"',
                'site:{domain} inurl:"debug_mode=1"',
                'site:{domain} inurl:"development=1"',
                'site:{domain} inurl:"testing=true"',
                'site:{domain} inurl:"staging=1"',
                'site:{domain} inurl:"show_errors=1"',
                'site:{domain} inurl:"error_reporting=1"',
                'site:{domain} inurl:"print_errors=1"',
                'site:{domain} inurl:"log_errors=1"',
                'site:{domain} inurl:"display_errors=1"',
                'site:{domain} inurl:"exception=1"',
                'site:{domain} inurl:"stacktrace=1"',
                'site:{domain} inurl:"dump=1"',
                'site:{domain} inurl:"phpinfo=1"',
                'site:{domain} inurl:"info=1"',
            ]
        }
    
    def get_all_dorks(self):
        """Get all dorks as a flat list"""
        all_dorks = []
        for category, dorks in self.dorks.items():
            all_dorks.extend([(category, dork) for dork in dorks])
        return all_dorks
    
    def get_dorks_by_category(self, category):
        """Get dorks for specific category"""
        return self.dorks.get(category, [])
    
    def get_categories(self):
        """Get all available categories"""
        return list(self.dorks.keys())
    
    def get_high_priority_dorks(self):
        """Get high-priority dorks for quick scanning"""
        priority_categories = ["sql_injection", "xss_vulnerabilities", "local_file_inclusion", "exposed_files"]
        high_priority = []
        
        for category in priority_categories:
            # Take first 5 dorks from each priority category
            category_dorks = self.get_dorks_by_category(category)
            high_priority.extend([(category, dork) for dork in category_dorks[:5]])
        
        return high_priority
    
    def get_dork_count(self):
        """Get total count of dorks"""
        return sum(len(dorks) for dorks in self.dorks.values())
