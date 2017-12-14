# This is the site level storybook

# override library functions and add your site level functions here

#Examples:-

# General:-

# if you do not use local files then overide these as follows:-

#function(localcheckrequest)
#if(true) return false

#function(localsslrequestcheck)
#if(true) return false

#To disable checks on embedded urls  
#
#function(embeddedcheck)
#if(true) return false



# For ICAP mode:-

# Override icapsquidbump to return true if you are using squid bump 
#  for https interception.
#
#function(icapsquidbump)
#if(true) return true
