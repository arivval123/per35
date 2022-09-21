<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Request\LoginRequest;
use App\Http\Request\RegisterRequest;
use App\Models\User;
use App\Traints\ApiResponse;
use Illuminate\Http\Exceptions\HtttpResponseException;
use Illuminate\Http\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function register(Request $request) 
    {
      //validasi
      $data = Validator::make($request->all(), [
        'name' => 'required',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:8',
        'confirmPassword' => 'required|same:password'
      ]);

      $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => Hash::make($request->password)
      ]);
}

public function login(Request $request) 
{
 $validated = $request->validated();

 if(!Auth::attempt($validated)){
    return $this->apiError('Credentials not match', Response::HTTP_UNAUTHORIZED);
 }
 $user = User::Where('email',$validated['email'])->first();
 $token= $user->createToken('auth_token')->plainTextToken;

 return $this->apiSuccess([
    'token' => $token,
    'token_type' => 'Bearer',
    'user' => $user,
 ]);
}

 public function logout()
 {
  try{
      auth()->user()->tokrns()->delete();
      return $this->apiSuccess('Tokones revoked');
  } catch (\Throwable $e){
    throw new HttpResponseException($this->apiError(
      null,
      Response::HTTP_INTERNAL_SERVER_ERROR
    ));
  }

 }

}