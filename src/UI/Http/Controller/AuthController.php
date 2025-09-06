<?php

declare(strict_types=1);

namespace App\UI\Http\Controller;

use App\Domain\Enum\UserRoleEnum;
use Firebase\JWT\JWK;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Firebase\JWT\JWT;

#[Route('/api/auth', name: 'api_auth_')]
class AuthController
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly JWTTokenManagerInterface $jwtManager,
        private readonly string $apiUserUrl,
        private readonly string $apiCompanyUrl,
    ) {}

    //http://localhost:8081/api/auth/login-cms
    #[Route('/login-cms', name: 'login-cms', methods: ['POST'])]
    public function checkAccess(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $response = $this->httpClient->request('POST', 'http://keycloak:8080/realms/sandbox/protocol/openid-connect/token', [
            'body' => [
                'grant_type' => 'password',
                'client_id' => 'sandbox',
                'client_secret' => '',
                'username' => $data['email'],
                'password' => $data['password'],
                'scope' => 'openid profile email',
            ],
        ]);

        if ($response->getStatusCode() !== 200) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        $tokenData = $response->toArray();
        $accessToken = $tokenData['access_token'];

        $companyResponse = $this->httpClient->request('POST', $this->apiCompanyUrl . '/security/check-company', [
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $accessToken,
            ],
            'json' => [
                'companyShortName' => $data['companyShortName']
            ],
        ]);

        $companyData = $companyResponse->toArray();

        $jwks = json_decode(file_get_contents('http://keycloak:8080/realms/sandbox/protocol/openid-connect/certs'), true);
        $keys = JWK::parseKeySet($jwks);
        $decoded = JWT::decode($accessToken, $keys);

        if ($decoded->company_uuid !== $companyData['companyUuid']) {
            return new JsonResponse(['error' => 'User does not belong to this company'], 403);
        }

        if (!in_array(UserRoleEnum::ADMIN_CMS->value, $decoded->resource_access->sandbox->roles)) {
            return new JsonResponse(['error' => 'User does not have odpowiednie roles'], 403);
        }

        return new JsonResponse([
            'status' => 'ok',
            'user_uuid' => $decoded->user_uuid,
            'company_uuid' => $decoded->company_uuid,
            'roles' => $decoded->resource_access->sandbox->roles,
            'user_email' => $decoded->email,
            'token' => $tokenData,
        ]);
    }
}
