# This is the site level storybook

# override library functions and add your site level functions here

#Examples:-

# General:-

# If you do not use local files then uncomment:-
#function(localcheckrequest)
#function(localsslrequestcheck)

# To disable checks on embedded urls then uncomment:-
#
#function(embeddedcheck)
#if(true) return false

# If you have bypass enabled then comment out next line:-
function(checknobypasslists)

# If you have av scanning enabled then comment out next 2 lines:-
function(checknoscanlists)
function(checknoscantypes)


# For ICAP mode:-

# If you are using squid bump for https interception uncomment
# next 2 lines
#function(icapsquidbump)
#if(true) return true
