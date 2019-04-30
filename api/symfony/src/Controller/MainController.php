<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\JsonResponse;

class MainController extends AbstractController
{
    /**
     * @Route("/login", name="login", methods={"GET"})
     */
    public function login(){}

    /**
     * @Route("/profile", name="profile", methods={"GET"})
     */
    public function profile()
    {
        return new JsonResponse([]);
    }

}
