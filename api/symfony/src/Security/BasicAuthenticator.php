<?php

namespace App\Security;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Firebase\JWT\JWT;

class BasicAuthenticator extends AbstractGuardAuthenticator
{
    private $em;
    private $passwordEncoder;

    public function __construct(EntityManagerInterface $em, UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->em = $em;
        $this->passwordEncoder = $passwordEncoder;
    }

    public function supports(Request $request)
    {
        return 'login' === $request->attributes->get('_route');
    }

    public function getCredentials(Request $request)
    {
        if (!$basic = $request->headers->get('Authorization')) {
            throw new CustomUserMessageAuthenticationException(
                'Authorization header is not specified'
            );
        }

        if (!$request->headers->get('php-auth-user') || !$request->headers->get('php-auth-pw')) {
            throw new CustomUserMessageAuthenticationException(
                'Bad authorization header'
            );
        }

        return [
            'username' => $request->headers->get('php-auth-user'), 
            'password' => $request->headers->get('php-auth-pw')
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $user = $this->em->getRepository(\App\Entity\User::class)->findOneBy(['email' => $credentials['username']]);

        if (!$user) {
            throw new CustomUserMessageAuthenticationException(
                'Email could not be found.'
            );
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return $this->passwordEncoder->isPasswordValid($user, $credentials['password']);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $jwt = JWT::encode([
            'id' => $token->getUser()->getId(),
            'iat' => \strtotime('now'),
            'exp' => 21600
        ], JWTSecret::SECRET_KEY);

        return new JsonResponse(['token' => $jwt],  Response::HTTP_OK);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new JsonResponse(['message' => 'Authentication failed'], Response::HTTP_FORBIDDEN);
    } 

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new JsonResponse(['message' => 'Authentication Required'], Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
