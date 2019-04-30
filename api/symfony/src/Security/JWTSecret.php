<?php

namespace App\Security;

abstract class JWTSecret
{
    const SECRET_KEY = 'I am a JSON Web Token secret key, used to encode signature.';
}
