#!/bin/bash

if [ -f .env ]; then
  echo 'find local .env ~ load new env';
  export $(cat .env | xargs);
  env;
fi

exec "$@";
