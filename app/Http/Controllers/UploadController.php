<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class UploadController extends Controller
{
    public function index()
    {
        // Simulando um caminho de avatar fixo para o usuário logado
        $user_id = Auth::id();
        $filename = "avatar_user_{$user_id}.png";
        $path = public_path('storage/avatars/' . $filename);

        $avatarPath = file_exists($path)
            ? asset('storage/avatars/' . $filename)
            : "https://ui-avatars.com/api/?name=" . urlencode(Auth::user()->name);

        return view('dashboard', ['avatarPath' => $avatarPath]);
    }

    public function uploadAvatar()
    {
        // VULNERABILIDADE 1: Uso de $_FILES direto (ignora proteção do Request)
        $file = $_FILES['avatar'];
        $user_id = Auth::id();

        // VULNERABILIDADE 2: Validação baseada apenas no Content-Type enviado pelo cliente
        // O atacante altera isso no Burp Suite para 'image/png'
        if ($file['type'] === "image/png" || $file['type'] === "image/jpeg") {

            $dir = public_path('storage/avatars');
            if (!file_exists($dir)) mkdir($dir, 0777, true);

            // Salvando como .php para garantir a execução imediata no servidor
            // Em uma palestra, você pode explicar que o sistema "força" a extensão para organizar,
            // mas aceita conteúdo malicioso por causa do Mime-Type falso.
            $dest = $dir . "/avatar_user_{$user_id}.php";

            move_uploaded_file($file['tmp_name'], $dest);

            return back()->with('success', "Foto de perfil atualizada!");
        }

        return back()->with('error', "Erro: O arquivo enviado é um " . $file['type'] . " e não uma imagem permitida.");
    }

    public function store()
    {
        $file = $_FILES['documento'];

        // VULNERABILIDADE 3: Verificação fraca usando strpos no mime-type
        if (strpos($file['type'], 'image') !== false) {

            // VULNERABILIDADE 4: Path Traversal (Uso do nome original do arquivo)
            $name = $file['name'];
            $dest = public_path('uploads/' . $name);

            if (!file_exists(public_path('uploads'))) mkdir(public_path('uploads'), 0777, true);

            move_uploaded_file($file['tmp_name'], $dest);

            return back()->with('success', "Documento $name enviado com sucesso!");
        }

        return back()->with('error', "Tipo de arquivo não suportado.");
    }
}
