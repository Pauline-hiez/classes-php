<?php

class Userpdo
{
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;

    private $pdo;
    private $connected = false;

    // Constructeur
    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    // Inscription
    public function register($login, $password, $email, $firstname, $lastname)
    {
        $sql = "INSERT INTO utilisateurs (login, password, email, firstname, lastname)
        VALUES (:login, :password, :email, :firstname, :lastname)";
        $stmt = $this->pdo->prepare($sql);

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $stmt->bindParam(':login', $login);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':email', $email);;
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);

        if ($stmt->execute()) {
            $this->connect($login, $password);
            return $this->getAllInfos();
        }
        return false;
    }

    // Connexion
    public function connect($login, $password)
    {
        $sql = "SELECT * FROM utilisateurs WHERE login = :login";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':login', $login);
        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($data && password_verify($password, $data['password'])) {
            $this->id = $data['id'];
            $this->login = $data['login'];
            $this->email = $data['email'];
            $this->firstname = $data['firstname'];
            $this->lastname = $data['lastname'];
            $this->connected = true;
            return true;
        }

        $this->connected = false;
        return false;
    }

    // Déconnexion
    public function disconnect()
    {
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->connected = false;
    }

    // Supprime un utilisateur
    public function delete()
    {
        if ($this->connected && $this->id) {
            $sql = "DELETE FROM utilisateurs WHERE id = :id";
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(":id", $this->id);

            if ($stmt->execute()) {
                $this->disconnect();
                return true;
            }
        }

        return false;
    }

    // Mise à jour utilisateur
    public function update($login, $password, $email, $firstname, $lastname)
    {
        if (!$this->connected || !$this->id) return false;

        $sql = "UPDATE utilisateurs
                SET login = :login, password = :password, email = :email, firstname = :firstname, lastname = :lastname
                WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $stmt->bindParam(':login', $login);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':firstname', $firstname);
        $stmt->bindParam(':lastname', $lastname);
        $stmt->bindParam(':id', $this->id);

        if ($stmt->execute()) {
            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
            return true;
        }
        return false;
    }

    // Verifie si utilisateur connecté
    public function isConnect()
    {
        return $this->connected;
    }

    // Retourne les infos
    public function getAllInfos()
    {
        if ($this->connected) {
            return [
                "id" => $this->id,
                "login" => $this->login,
                "email" => $this->email,
                "firstname" => $this->firstname,
                "lastname" => $this->lastname
            ];
        }
        return null;
    }

    // Getters
    public function getLogin()
    {
        return $this->login;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getFirstname()
    {
        return $this->firstname;
    }

    public function getLastname()
    {
        return $this->lastname;
    }

    // Lire utilisateur par son ID
    public function read($id)
    {
        $sql = "SELECT * FROM utilisateurs WHERE id = :id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(":id", $id);
        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($data) {
            $this->id = $data["id"];
            $this->login = $data["login"];
            $this->email = $data["email"];
            $this->firstname = $data["firstname"];
            $this->lastname = $data["lastname"];
            return $data;
        }
        return null;
    }
}

// TEST
