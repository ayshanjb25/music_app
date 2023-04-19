<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request; 
use App\Http\Controllers\Controller; 
use App\User;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response; 
use Validator;
use Illuminate\Support\Str;

class UserController extends Controller 
{
public $successStatus = 200;

/** 
     * Register api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    public function register(Request $request) 
    { 
        $validator = Validator::make($request->all(), [ 
            'first_name' => 'required',
            'last_name' => 'required',
            'nickname' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'dob' => 'required',
            'mobile'=>'required',
            'gender'=>'required'
        ]);
        if ($validator->fails()) { 
            return response()->json(['error'=>$validator->errors()], 401);            
        }
        // $input = $request->all(); 
        // $input['password'] = bcrypt($input['password']); 
        // $user = User::create($input); 
        // $success['access_token'] =  $user->createToken('MyApp')-> accessToken; 
        // //$success['name'] =  $user->name;
        // return response()->json(['success'=>$success], $this-> successStatus); 
        
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        // generate a random string of 20 characters
       $access_token = $user->createToken('access_token');
        $success['access_token'] = $access_token;

        return response()->json(['success' => $success], $this->successStatus);


    }

    /** 
     * login api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    //public function login(Request $request){ 
        // if(Auth::attempt(['email' => request('email'), 'password' => request('password')])){ 
        //     $user = Auth::user(); 
        //     $success['access_token'] =  $user->createToken('MyApp')-> accessToken; 
        //     return response()->json(['success' => $success], $this-> successStatus); 
        // } 
        // else{ 
        //     return response()->json(['error'=>'Unauthorised'], 401); 
        // } 



        // $creds = $request->only(['email','password']);
        // if (!$access_token=auth()->attempt($creds)){
        //     return response()->json([
        //         'success'=>false,
        //         'message'=>'information incorrecte'
        //     ],Response::HTTP_UNAUTHORIZED);
        // }
        // return response()->json([
        //     'success'=>true,
        //     'token'=>$access_token,
        //     'user'=>Auth::user()
        // ],Response::HTTP_OK);
     //}

    public function login(Request $request)
    {
        $user = $request->validate([
                'email' => 'required|email',
                'password' => 'required|string'
        ]);

        if(!Auth::attempt($user)){
            return response(['code'=>0, 'message'=>'Invalid Authentications']);
        }
        $token = Auth::user()->createToken('Personal');
        return $token;

    }


    /**
 * Login user and create access token
 *
 * @param  \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\Response
 */
// public function login(Request $request)
// {
//     $validator = Validator::make($request->all(), [
//         'email' => 'required|email',
//         'password' => 'required',
//     ]);

//     if ($validator->fails()) {
//         return response()->json(['error' => $validator->errors()], 401);
//     }

//     if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
//         $user = Auth::user();
//         $token = $user->createToken('access_token')->accessToken;
//         return response()->json(['access_token' => $token], 200);
//     } else {
//         return response()->json(['error' => 'Unauthenticated'], 401);
//     }
// }
    // public function login(){ 
        
    //     $user = User::select('*')->where('email', 'aisha@outlook.co')->first(); 
    //     $success['token'] =  $user->createToken('MyApp')-> accessToken; 
    //     return response()->json(['success' => $success], $this-> successStatus); 
        
    // }
/** 
     * details api 
     * 
     * @return \Illuminate\Http\Response 
     */ 
    public function details() 
    { 
        $user = Auth::user(); 
        return response()->json(['success' => $user], $this-> successStatus); 
    } 
}
