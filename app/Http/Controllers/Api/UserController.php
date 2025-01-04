<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;


class UserController extends Controller
{
      /**
         * Create User
         * @param Request $request
         * @return User
         */

         
    /*    public function createUser(Request $request)
        {
            try {
                //Validated
                $validateUser = Validator::make($request->all(),
                [
                    'avatar' => 'required',
                    'type' => 'required',
                    'open_id' => 'required',
                    'name' => 'required',
                    'email' => 'required|email|unique:users,email',
                    'password' => 'required|min:6'
                ]);

                if($validateUser->fails()){
                    return response()->json([
                        'status' => false,
                        'message' => 'validation error',
                        'errors' => $validateUser->errors()
                    ], 401);
                }
                $validateUser = $validateUser->validated();

                $map = [];
                //email, phone, google, facebook, apple
                $map['type'] = $validateUser['type'];
                $map['open_id'] = $validateUser['open_id'];

                $user = User::where($map) ->first();

                //Whether user has already logged in or not
                //empty means user does not exist
                //then save the user in the database for the first time
                if(empty($user -> id)){
                    //this certain user has never been in our databse
                    //our job is to assign the user in the database
                    $validated["token"] = md5(uniqid().rand(10000, 99999));

                    //user first time created
                    $validated['created_at'] = Carbon::now();

                    // encrypt password
                    $validated['password'] = Hash::make($validated['password']);

                    $validated['password'] = Hash::make($validated);


                    //returns id of the row after saving
                    $userID = User::insertGetId($validated);

                    //all user information
                    $userInfo =  User::where('id', '=', $userID)->first();

                    $accessToken = $userInfo -> createToken(uniqid()) -> plainTextToken;

                    $userInfo -> access_token = $accessToken;

                    User::where( 'id', '=', $userID) -> update( ['access_token'=>$accessToken]);
                    
                    return response()->json([
                        'status' => true,
                        'message' => 'User Created Successfully',
                        'token' => $userInfo
                    ], 200);
    

                }
        
                // Existing user flow
                $userInfo = $user; // Assign the existing user to $userInfo

                $accessToken = $userInfo -> createToken(uniqid()) -> plainTextToken;
                $userInfo -> access_token = $accessToken;
   //             User::where(column: 'open_id', '=', $validated['open_id'])->update(['access_token'=>$accessToken]);


                return response()->json([
                    'status' => true,
                    'message' => 'User logged in Successfully',
                    'token' => $userInfo
                ], 200);

            } catch (\Throwable $th) {
                return response()->json([
                    'status' => false,
                    'message' => $th->getMessage()
                ], 500);
            }
        }*/

public function createUser(Request $request)
{
    try {
        // Validate the request
        $validateUser = Validator::make($request->all(), [
            'avatar' => 'required',
            'type' => 'required',
            'open_id' => 'required',
            'name' => 'required',
            'email' => 'required',
            'password' => 'required|min:6'
        ]);

        if ($validateUser->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Validation error',
                'errors' => $validateUser->errors(),
            ], 401);
        }

        $validateUser = $validateUser->validated();

                        
        //email, phone, google, facebook, apple
        $map = [
            'type' => $validateUser['type'],
            'open_id' => $validateUser['open_id'],
        ];

        $user = User::where($map)->first();

        // Check if the user exists
        if (empty($user)) {
            // New user creation
            $validateUser["token"] = md5(uniqid() . rand(10000, 99999));
            $validateUser['created_at'] = Carbon::now();
            $validateUser['password'] = Hash::make($validateUser['password']);

            // Insert the new user and fetch the ID
            $userID = User::insertGetId($validateUser);

            // Fetch user info
            $userInfo = User::find($userID);
            $accessToken = $userInfo->createToken(uniqid())->plainTextToken;

            return response()->json([
                'status' => true,
                'message' => 'User Created Successfully',
                'user' => $userInfo,
                'token' => $accessToken,
            ], 200);
        }

        //User has logged in
        // Existing user flow
        $accessToken = $user->createToken(uniqid())->plainTextToken;

        $user -> access_token = $accessToken;
        User::where('open_id', '=', $validateUser['open_id'])->update(['access_token'=>$accessToken]);
        return response()->json([
            'status' => true,
            'message' => 'User logged in Successfully',
            'user' => $user,
            'token' => $accessToken,
        ], 200);

    } catch (\Throwable $th) {
        return response()->json([
            'status' => false,
            'message' => $th->getMessage(),
        ], 500);
    }
}


        /**
         * Login The User
         * @param Request $request
         * @return User
         */
        public function loginUser(Request $request)
        {
            try {
                $validateUser = Validator::make($request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required'
                ]);

                if($validateUser->fails()){
                    return response()->json([
                        'status' => false,
                        'message' => 'validation error',
                        'errors' => $validateUser->errors()
                    ], 401);
                }

                if(!Auth::attempt($request->only(['email', 'password']))){
                    return response()->json([
                        'status' => false,
                        'message' => 'Email & Password does not match with our record.',
                    ], 401);
                }

                $user = User::where('email', $request->email)->first();

                return response()->json([
                    'status' => true,
                    'message' => 'User Logged In Successfully',
                    'token' => $user->createToken("API TOKEN")->plainTextToken
                ], 200);

            } catch (\Throwable $th) {
                return response()->json([
                    'status' => false,
                    'message' => $th->getMessage()
                ], 500);
            }
        }
}
