<?php

declare(strict_types=1);

namespace Modules\Api\Rest\V1\Filters;

use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\Request;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Entities\User;
use Config\Services;
use Modules\Api\Rest\V1\Config\RestApi;
use Modules\Auth\Models\UserModel;

class ApiFilter implements FilterInterface
{
    /**
     * @param Request $request
     * @return RequestInterface|ResponseInterface|string|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        /** @var RestApi $restApiConfig */
        $restApiConfig = config('RestApi');

        if (! $restApiConfig->enabled) {
            throw PageNotFoundException::forPageNotFound();
        }

        if ($restApiConfig->basicAuth) {
            /** @var Response $response */
            $response = service('response');
            if (! $request->hasHeader('Authorization')) {
                $response->setStatusCode(401);

                return $response;
            }

            $authHeader = $request->getHeaderLine('Authorization');
            if (! str_starts_with($authHeader, 'Basic ')) {
                $response->setStatusCode(401);

                return $response;
            }

            $auth_token = base64_decode(substr($authHeader, 6), true);

            [$username, $password] = explode(':', (string) $auth_token);

            if (! ($username === $restApiConfig->basicAuthUsername && $password === $restApiConfig->basicAuthPassword)) {
                $response->setStatusCode(401);

                return $response;
            }

            // Get the IncomingRequest instance
            /** @var IncomingRequest $incomingRequest */
            $incomingRequest = Services::request();

            if ($incomingRequest->getMethod() === 'post' && ($incomingRequest->getPost(
                'user_id'
            ) || $incomingRequest->getPost('updated_by'))) {
                $user_id = $incomingRequest->getPost('user_id');
                $updated_by = $incomingRequest->getPost('updated_by');

                if (! is_scalar($user_id) || ! is_scalar($updated_by)) {
                    $response->setStatusCode(400); // Bad Request

                    return $response;
                }

                if (! $user_id || ! $updated_by) {
                    $response->setStatusCode(401);

                    return $response;
                }

                $userModel = new UserModel();

                /** @var User|null $user */
                $user = $userModel->find($user_id);

                /** @var User|null $updatedByUser */
                $updatedByUser = $userModel->find($updated_by);

                if (
                    ! $user instanceof User ||
                    ! $updatedByUser instanceof User
                ) {
                    $response->setStatusCode(401);
                    return $response;
                }

                if (
                    ! $user->can('create-episode') ||
                    ! $updatedByUser->can('create-episode')
                ) {
                    $response->setStatusCode(403);
                    return $response;
                }

                if (
                    ! $user->can('update-episode') ||
                    ! $updatedByUser->can('update-episode')
                ) {
                    $response->setStatusCode(403);
                    return $response;
                }
            }
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): void
    {
        // Do something here
    }
}
