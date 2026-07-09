<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class LoginController extends AbstractController
{
    #[Route('/api/login', methods: ['POST'])]
    public function login(Request $request): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $username = $request->request->get('username');
        // SQL injection via raw query
        $conn = $this->getDoctrine()->getConnection();
        $result = $conn->fetchAllAssociative(
            "SELECT * FROM users WHERE username = '" . $username . "'"
        );
        return $this->json($result);
    }

    #[Route('/admin', methods: ['GET'])]
    public function admin(): \Symfony\Component\HttpFoundation\Response
    {
        $data = unserialize($_COOKIE['data'] ?? '');  // PHP object injection
        return $this->render('admin.html.twig', ['data' => $data]);
    }
}
