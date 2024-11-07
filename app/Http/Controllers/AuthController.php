<?php

namespace App\Http\Controllers;

use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller{
    // ฟังก์ชันสำหรับการลงทะเบียนผู้ใช้ใหม่
    public function register(Request $request)
    {
        // Validating the input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        // ถ้า validation ล้มเหลว, ส่งข้อความผิดพลาด
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        try {
            // การสร้างผู้ใช้ใหม่
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            // ส่ง response กลับพร้อมกับข้อมูลผู้ใช้
            return response()->json([
                'user' => $user,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'An error occurred while registering the user.',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // ฟังก์ชันสำหรับการเข้าสู่ระบบ
    public function login(Request $request)
    {
        // Validate the login credentials
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // Check if user exists
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // สร้าง access token ด้วยเวลา expiration 1 นาที (60 วินาที)
        $accessToken = $user->createToken('access_token')->plainTextToken;

        // เก็บเวลา expiration ของ access token (1 นาที)
        $accessTokenExpiry = now()->addMinutes(1); // 1 นาทีจากนี้

        // เก็บเวลา expiry ของ access token ในฐานข้อมูล
        $user->access_token_expiry = $accessTokenExpiry;
        $user->save();

        // สร้าง refresh token (เก็บไว้ในฐานข้อมูล หรือใช้ random string)
        $refreshToken = Str::random(64); // สร้าง refresh token ใหม่

        // กำหนดเวลาให้ refresh token หมดอายุใน 2 นาที (120 วินาที)
        $refreshTokenExpiry = now()->addMinutes(2); // ใช้เวลาปัจจุบันบวก 2 นาที

        // เก็บ refresh token และเวลาหมดอายุในฐานข้อมูล
        $user->refresh_token = $refreshToken;
        $user->refresh_token_expiry = $refreshTokenExpiry;
        $user->save();

        // ส่งกลับ access token และ refresh token พร้อมเวลา expiration
        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'access_token' => $accessToken,
                'access_token_expiry' => $accessTokenExpiry,
                'refresh_token' => $refreshToken,
                'refresh_token_expiry' => $refreshTokenExpiry,
            ],
        ]);
    }


    public function refresh(Request $request)
    {
        $refreshToken = $request->input('refresh_token');

        // ตรวจสอบว่า refresh token มีหรือไม่
        $user = User::where('refresh_token', $refreshToken)
                    ->where('refresh_token_expiry', '>', now()) // ตรวจสอบว่า refresh token ยังไม่หมดอายุ
                    ->first();

        if (!$user) {
            return response()->json(['message' => 'Invalid or expired refresh token'], 401);
        }
        
        // ลบ access token เก่าทุกตัว (ทำให้ไม่สามารถใช้ได้)
        $user->tokens->each(function ($token) {
            $token->delete(); // ลบ access token เก่าที่ไม่ใช้งาน
        });

        // สร้าง access token ใหม่
        $newAccessToken = $user->createToken('access_token')->plainTextToken;

        // กำหนดเวลา expiration ของ access token ใหม่ (1 นาที)
        $accessTokenExpiry = now()->addMinutes(1); // 1 นาทีจากนี้
        
        // อัพเดตเวลา expiration ของ access token ใหม่ในฐานข้อมูล
        $user->access_token_expiry = $accessTokenExpiry;
        $user->save();

        return response()->json([
            'access_token' => $newAccessToken,
            'token_type' => 'Bearer',
            'expires_in' => 60, // 1 นาที (60 วินาที)
        ]);
    }

    // ฟังก์ชันสำหรับการออกจากระบบ (Logout)
    public function logout(Request $request)
    {
        // ลบ token ที่ถูกสร้างขึ้นสำหรับผู้ใช้
        $request->user()->tokens->each(function ($token) {
            $token->delete();
        });

        // ส่งข้อความตอบกลับว่า logout สำเร็จ
        return response()->json(['message' => 'Successfully logged out']);
    }

    // ฟังก์ชันสำหรับการอัปเดตข้อมูลผู้ใช้
    public function update(Request $request, $id)
    {
        // ค้นหาผู้ใช้ตาม ID
        $user = User::find($id);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // ตรวจสอบข้อมูลที่ต้องการอัปเดต
        $request->validate([
            'name' => 'nullable|string|max:255',
            'email' => 'email|unique:users,email,' . $id,
            'password' => 'nullable|min:6|confirmed'
        ]);

        // อัปเดตข้อมูลของผู้ใช้
        if ($request->has('name')) {
            $user->name = $request->name;
        }

        if ($request->has('email')) {
            $user->email = $request->email;
        }

        if ($request->has('password')) {
            $user->password = Hash::make($request->password);
        }

        $user->save();

        return response()->json(['message' => 'User updated successfully', 'user' => $user]);
    }

    //ฟังก์ชันลบผู้ใช้
    public function delete($id)
    {
        // ค้นหาผู้ใช้ตาม ID
        $user = User::find($id);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // ลบผู้ใช้
        $user->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }

    // ฟังก์ชันสำหรับการตรวจสอบข้อมูลผู้ใช้
    public function getUser(Request $request)
    {
        // ตรวจสอบว่า user login แล้วหรือยัง
        $user = Auth::user();

        // ถ้าไม่มีการล็อกอิน หรือ access token หมดอายุ
        if (!$user || $user->access_token_expiry < now()) {
            return response()->json(['message' => 'Access token expired or not authenticated'], 401);
        }

        // ส่งกลับข้อมูลผู้ใช้
        return response()->json([
            'user' => $user
        ]);
    }



    
}

