<?php

namespace App\Http\Controllers;

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
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);

        // ถ้า validation ล้มเหลว, ส่งข้อความผิดพลาด
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // เช็คว่า user มีอยู่ในฐานข้อมูลหรือไม่
        $user = User::where('email', $request->email)->first();

        // ถ้าไม่มี user หรือรหัสผ่านไม่ตรง
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // สร้าง token สำหรับการเข้าสู่ระบบ
        $token = $user->createToken('YourAppName')->plainTextToken;

        // ส่ง response กลับพร้อมกับข้อมูลผู้ใช้และ token
        return response()->json([
            'user' => $user,
            'token' => $token,
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

    public function getUser(Request $request)
    {
        // ตรวจสอบว่าผู้ใช้ล็อกอินอยู่หรือไม่
        $user = Auth::user();

        if ($user) {
            return response()->json([
                'user' => $user
            ]);
        } else {
            return response()->json([
                'message' => 'Not authenticated'
            ], 401); // 401 Unauthorized
        }
    }
    
}

