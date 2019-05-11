export DJANGO_SECRET_KEY=''
export DEBUG=true
export DEFAULT_FROM_EMAIL='{{project_name}}@{{project_name}}.com'

export DATABASE_URL='postgres://{{project_name}}_user:{{project_name}}_pass@localhost:5432/{{project_name}}'

# auth
export {{project_name|upper}}_HOST='http://localhost:7000'
export EMAIL_VERIFICATION_LINK='/'
