<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthenticationController extends Controller
{
    public function register(RegisterRequest $registerRequest)
    {
        try {
            $registerRequest->validated();
            $userData = [
                'name' => $registerRequest->name,
                'username' => $registerRequest->username,
                'email' => $registerRequest->email,
                'password' => Hash::make($registerRequest->password),
            ];
            $user = User::create($userData);

            $token = $user->createToken('gmu_app')->plainTextToken;

            return response([
                'user' => $user,
                'token' => $token
            ], 201);
        } catch (\Exception $e) {
            $this->response($e);
        }
    }

    public function login(LoginRequest $loginRequest)
    {
        try {
            $loginRequest->validated();

            $user = User::whereUsername($loginRequest->username)->first();
            if (!$user || !Hash::check($loginRequest->password, $user->password)) {
                return response([
                    'message' => 'Invalid credentials'
                ], 422);
            }
    
            $token = $user->createToken('gmu_app')->plainTextToken;
    
            return response([
                'user' => $user,
                'token' => $token
            ], 200);

        } catch (\Exception $e) {
            $this->response($e);
        }
    }


    public function response($e)
    {
        return response([
            'message' => 'Exception',
            'stackTrace' => $e->getMessage()
        ]);
    }
}
