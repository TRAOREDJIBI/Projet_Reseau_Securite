import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
import hashlib
import os

class HashApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Outil de hachage SHA-2")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")  # Background color of the root window

        # Création des widgets de l'interface graphique
        self.create_widgets()

    def create_widgets(self):
        # Bouton pour choisir un fichier
        self.file_btn = tk.Button(self.root, text="Choisir un fichier", command=self.hash_file, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
        self.file_btn.pack(pady=10)

        # Bouton pour choisir un répertoire
        self.dir_btn = tk.Button(self.root, text="Choisir un répertoire", command=self.hash_directory, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
        self.dir_btn.pack(pady=10)

        # Zone de texte pour l'entrée de texte
        self.input_text_label = tk.Label(self.root, text="Entrez le texte à hacher:", bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        self.input_text_label.pack(fill='x', padx=10, pady=5)
        
        self.input_text = Text(self.root, height=5, wrap='word', bg="#ffffff", fg="#000000", font=("Helvetica", 12))
        self.input_text.pack(fill='both', expand=True, padx=10, pady=5)

        # Bouton pour hacher le texte entré
        self.hash_text_btn = tk.Button(self.root, text="Hacher le texte", command=self.hash_text, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
        self.hash_text_btn.pack(pady=10)

        # Bouton pour enregistrer les résultats
        self.save_btn = tk.Button(self.root, text="Enregistrer le résultat", command=self.save_result, bg="#2196F3", fg="white", font=("Helvetica", 12, "bold"))
        self.save_btn.pack(pady=10)

        # Étiquette pour les résultats de hachage
        self.result_label = tk.Label(self.root, text="Résultat du hachage:", anchor='w', bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        self.result_label.pack(fill='x', padx=10, pady=5)

        # Zone de texte pour afficher les résultats de hachage
        self.result_text = Text(self.root, height=10, wrap='none', bg="#ffffff", fg="#000000", font=("Helvetica", 12))
        self.result_text.pack(fill='both', expand=True, padx=10, pady=5)

        # Barre de défilement horizontale pour la zone de texte
        self.scroll_x = Scrollbar(self.root, orient='horizontal', command=self.result_text.xview, bg="#f0f0f0")
        self.scroll_x.pack(fill='x')
        self.result_text.config(xscrollcommand=self.scroll_x.set)

    def hash_file(self):
        # Ouvrir une boîte de dialogue pour choisir un fichier
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                # Calculer le hachage du fichier
                hash_result = self.calculate_file_hash(file_path)
                # Afficher le résultat
                self.display_result(f"Fichier: {file_path}\nSHA-256: {hash_result}\n\n")
            except Exception as e:
                # Afficher une erreur en cas de problème
                messagebox.showerror("Erreur", str(e))

    def hash_directory(self):
        # Ouvrir une boîte de dialogue pour choisir un répertoire
        dir_path = filedialog.askdirectory()
        if dir_path:
            try:
                result = ""
                # Parcourir tous les fichiers du répertoire
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Calculer le hachage de chaque fichier
                        hash_result = self.calculate_file_hash(file_path)
                        result += f"Fichier: {file_path}\nSHA-256: {hash_result}\n\n"
                # Afficher les résultats
                self.display_result(result)
            except Exception as e:
                # Afficher une erreur en cas de problème
                messagebox.showerror("Erreur", str(e))

    def hash_text(self):
        # Récupérer le texte entré par l'utilisateur
        input_str = self.input_text.get(1.0, tk.END).strip()
        if input_str:
            try:
                # Calculer le hachage du texte
                sha256_hash = hashlib.sha256(input_str.encode('utf-8')).hexdigest()
                # Afficher le résultat
                self.display_result(f"Texte: {input_str}\nSHA-256: {sha256_hash}\n\n")
            except Exception as e:
                # Afficher une erreur en cas de problème
                messagebox.showerror("Erreur", str(e))
        else:
            # Afficher un message d'avertissement si aucun texte n'est entré
            messagebox.showwarning("Attention", "Veuillez entrer du texte à hacher.")

    def calculate_file_hash(self, file_path):
        # Initialiser l'objet SHA-256
        sha256_hash = hashlib.sha256()
        # Ouvrir le fichier en mode binaire
        with open(file_path, "rb") as f:
            # Lire le fichier par blocs de 4096 octets
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        # Retourner le hachage en format hexadécimal
        return sha256_hash.hexdigest()

    def display_result(self, result):
        # Effacer le contenu précédent de la zone de texte
        self.result_text.delete(1.0, tk.END)
        # Insérer le nouveau résultat dans la zone de texte
        self.result_text.insert(tk.END, result)

    def save_result(self):
        # Ouvrir une boîte de dialogue pour choisir un répertoire de sauvegarde
        save_dir = filedialog.askdirectory()
        if save_dir:
            # Récupérer le texte des résultats de hachage
            result = self.result_text.get(1.0, tk.END)
            if result.strip():
                try:
                    # Écrire les résultats dans un fichier texte
                    with open(os.path.join(save_dir, "hash_results.txt"), "w") as f:
                        f.write(result)
                    # Afficher un message de succès
                    messagebox.showinfo("Succès", "Les résultats ont été enregistrés avec succès.")
                except Exception as e:
                    # Afficher une erreur en cas de problème
                    messagebox.showerror("Erreur", str(e))
            else:
                # Avertir si aucun résultat n'est disponible pour l'enregistrement
                messagebox.showwarning("Attention", "Il n'y a pas de résultats à enregistrer.")

if __name__ == "__main__":
    root = tk.Tk()
    app = HashApp(root)
    root.mainloop()