<?php

namespace App\Http\Controllers;

use App\Http\Requests\AuthRequest;
use Illuminate\Http\Request;
use Auth;
use App\Models\User;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Response;

class AuthController extends Controller
{
    public function __construct()
    {   
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(Request $request) 
    {   
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed|min:6'
        ]);

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));
        
        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], Response::HTTP_CREATED);
    }

    public function login(Request $request) 
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required'
        ]);

        if($validator->fails()) {
            return response()->json($validator->errors(), RESPONSE::HTTP_UNPROCESSABLE_ENTITY);
        }

        if(!$token=auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Invalid User'], RESPONSE::HTTP_UNAUTHORIZED);
        }

        return $this->createNewToken($token);
    }

    public function createNewToken($token) 
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL()*60
        ]);
    }

    public function profile() {
        return response()->json(auth()->user());
    }

    public function logout() 
    {
        auth()->logout();

        return response()->json(['message' => 'User logged out'], Response::HTTP_OK);
    }
}
