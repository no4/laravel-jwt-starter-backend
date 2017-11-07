<?php

namespace App\Providers;

use InvalidArgumentException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Providers\JWT\Namshi;

class BugfixedNamshiProvider extends Namshi
{
    /**
     * Decode a JSON Web Token.
     *
     * @param  string $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return array
     */
    public function decode($token)
    {
        // Fix bug with jwt-auth package
        if ($token[0] == ':' && $token[1] == ' ') {
            $token = substr($token, 2);
        }

        try {
            // Let's never allow insecure tokens
            $jws = $this->jws->load($token, false);
        } catch (InvalidArgumentException $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if (!$jws->verify($this->getVerificationKey(), $this->getAlgo())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (array) $jws->getPayload();
    }
}