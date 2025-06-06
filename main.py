import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import json
from collections import Counter
import string
import nltk
import re
import math
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
}

nltk.download('words', quiet=True)
from nltk.corpus import words

ENGLISH_WORDS = set(w.lower() for w in words.words())


def load_quadgram_stats(filename):
    quadgrams = {}
    total = 0
    with open(filename, 'r') as f:
        for line in f:
            key, count = line.split()
            quadgrams[key] = int(count)
            total += int(count)
    for key in quadgrams:
        quadgrams[key] = math.log10(quadgrams[key] / total)
    floor = math.log10(0.01 / total)
    return quadgrams, floor


def quadgram_score(text, quadgrams, floor):
    score = 0
    text = text.upper()
    for i in range(len(text) - 3):
        quad = text[i:i + 4]
        if quad in quadgrams:
            score += quadgrams[quad]
        else:
            score += floor
    return score


def hill_climb(ciphertext, quadgrams, floor, max_iterations=10000, stagnation_limit=2000, progress_callback=None):
    alphabet = list(string.ascii_uppercase)
    parent = alphabet[:]
    random.shuffle(parent)
    parent_score = quadgram_score(substitute(ciphertext, dict(zip(alphabet, parent))), quadgrams, floor)
    best = parent[:]
    best_score = parent_score

    no_improve = 0

    for i in range(max_iterations):
        child = parent[:]
        a, b = random.sample(range(26), 2)
        child[a], child[b] = child[b], child[a]
        child_score = quadgram_score(substitute(ciphertext, dict(zip(alphabet, child))), quadgrams, floor)

        if child_score > parent_score:
            parent = child
            parent_score = child_score
            no_improve = 0
            if parent_score > best_score:
                best = parent
                best_score = parent_score
        else:
            no_improve += 1

        if no_improve >= stagnation_limit:
            break

        if progress_callback and i % 100 == 0:
            progress_callback(i / max_iterations * 100)

    if progress_callback:
        progress_callback(100)

    return dict(zip(alphabet, best)), best_score



# Substitution function
def substitute(text, key_map):
    result = []
    for char in text:
        if char.upper() in key_map:
            repl = key_map[char.upper()]
            if char.islower():
                result.append(repl.lower())
            else:
                result.append(repl.upper())
        else:
            result.append(char)
    return ''.join(result)


# Letter frequency analyzer
def letter_frequency(text):
    filtered = [c.upper() for c in text if c.upper() in string.ascii_uppercase]
    total = len(filtered)
    count = Counter(filtered)
    return {char: round(count[char] / total, 4) if total > 0 else 0.0 for char in string.ascii_uppercase}


# Highlight likely English words in the output
def highlight_english_words(text, text_widget):
    text_widget.tag_remove("highlight", "1.0", tk.END)
    words_in_text = re.finditer(r"\b[a-zA-Z]{3,}\b", text)
    for match in words_in_text:
        word = match.group().lower()
        if word in ENGLISH_WORDS:
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            text_widget.tag_add("highlight", start, end)
    text_widget.tag_config("highlight", background="yellow")


class SubstitutionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Substitution Cipher Tool")
        self.score_var = tk.StringVar(value="Score: N/A")
        self.score_label = ttk.Label(self.root, textvariable=self.score_var)
        self.score_label.pack()
        self.create_widgets()

    def create_widgets(self):
        self.input_label = ttk.Label(self.root, text="Input Text:")
        self.input_label.pack()
        self.input_text = tk.Text(self.root, height=5, width=80)
        self.input_text.pack()

        key_io_frame = ttk.Frame(self.root)
        key_io_frame.pack(pady=5)
        self.save_key_btn = ttk.Button(key_io_frame, text="导出密钥", command=self.export_key)
        self.save_key_btn.grid(row=0, column=0, padx=5)
        self.load_key_btn = ttk.Button(key_io_frame, text="导入密钥", command=self.import_key)
        self.load_key_btn.grid(row=0, column=1, padx=5)

        self.key_frame = ttk.LabelFrame(self.root, text="Substitution Key (A-Z)")
        self.key_frame.pack()
        self.key_vars = {}
        for i, char in enumerate(string.ascii_uppercase):
            ttk.Label(self.key_frame, text=char).grid(row=0, column=i)
            var = tk.StringVar(value=char)
            ttk.Entry(self.key_frame, width=2, textvariable=var).grid(row=1, column=i)
            self.key_vars[char] = var

        self.encrypt_btn = ttk.Button(self.root, text="Encrypt", command=self.encrypt_text)
        self.encrypt_btn.pack(pady=5)
        self.decrypt_btn = ttk.Button(self.root, text="Decrypt", command=self.decrypt_text)
        self.decrypt_btn.pack(pady=5)

        self.auto_decrypt_btn = ttk.Button(self.root, text="自动解密", command=self.auto_decrypt)
        self.auto_decrypt_btn.pack(pady=5)

        iter_frame = ttk.Frame(self.root)
        iter_frame.pack()

        self.iter_label = ttk.Label(iter_frame, text="最大迭代次数:")
        self.iter_label.grid(row=0, column=0, padx=5)
        self.iter_entry = ttk.Entry(iter_frame, width=8)
        self.iter_entry.insert(0, "10000")
        self.iter_entry.grid(row=0, column=1)

        self.restart_label = ttk.Label(iter_frame, text="Hill Climb 重启次数:")
        self.restart_label.grid(row=0, column=2, padx=10)
        self.restart_entry = ttk.Entry(iter_frame, width=5)
        self.restart_entry.insert(0, "50")
        self.restart_entry.grid(row=0, column=3)


        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=5)

        self.output_label = ttk.Label(self.root, text="Output Text:")
        self.output_label.pack()
        self.output_text = tk.Text(self.root, height=5, width=80)
        self.output_text.pack()

        self.freq_chart_btn = ttk.Button(self.root, text="频率分析", command=self.show_frequency_chart)
        self.freq_chart_btn.pack(pady=5)

        
    def export_key(self):
        key_map = self.get_key_map()
        filepath = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON Files", "*.json")],
                                                title="保存密钥")
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(key_map, f)
            messagebox.showinfo("导出成功", f"密钥已保存至：{filepath}")

    def import_key(self):
        filepath = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")],
                                            title="导入密钥")
        if filepath:
            with open(filepath, 'r') as f:
                key_map = json.load(f)
            for char in string.ascii_uppercase:
                if char in key_map and key_map[char] in string.ascii_uppercase:
                    self.key_vars[char].set(key_map[char])
            messagebox.showinfo("导入成功", f"密钥已加载：{filepath}")


    def update_score(self, text):
        quadgrams, floor = load_quadgram_stats("english_quadgrams.txt")
        score = quadgram_score(text, quadgrams, floor)
        self.score_var.set(f"Score: {score:.2f}")

    def hill_climb_callback(self, current, total, score):
        self.progress["value"] = (current / total) * 100
        self.score_var.set(f"Score: {score:.2f}")
        self.root.update_idletasks()

    def auto_decrypt(self):
            text = self.input_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("警告", "请输入密文")
                return

            try:
                max_iter = int(self.iter_entry.get())
                NUM_RESTARTS = int(self.restart_entry.get())
            except:
                max_iter = 10000
                NUM_RESTARTS = 50

            self.progress['value'] = 0
            self.score_var.set("正在自动解密中... 请稍候")
            self.root.update_idletasks()

            quadgrams, floor = load_quadgram_stats("english_quadgrams.txt")

            best_score = float('-inf')
            best_result = ""
            best_key = {}

            for r in range(NUM_RESTARTS):
                def update_progress(val):
                    self.progress['value'] = ((r + val / 100) / NUM_RESTARTS) * 100
                    self.root.update_idletasks()

                key, score = hill_climb(text, quadgrams, floor, max_iterations=max_iter,
                                        stagnation_limit=2000, progress_callback=update_progress)
                result = substitute(text, key)
                if score > best_score:
                    best_score = score
                    best_result = result
                    best_key = key

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, best_result)
            for char in string.ascii_uppercase:
                self.key_vars[char].set(best_key[char])

            highlight_english_words(best_result, self.output_text)
            self.update_score(best_result)
            self.score_var.set(f"自动解密完成，最佳分数: {best_score:.2f}")


    def get_key_map(self):
        key_map = {}
        for char in string.ascii_uppercase:
            val = self.key_vars[char].get().upper()
            key_map[char] = val if val in string.ascii_uppercase else char
        return key_map

    def encrypt_text(self):
        text = self.input_text.get("1.0", tk.END).strip()
        key_map = self.get_key_map()
        result = substitute(text, key_map)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)
        highlight_english_words(result, self.output_text)

    def decrypt_text(self):
        text = self.input_text.get("1.0", tk.END).strip()
        key_map = self.get_key_map()
        reverse_key = {v: k for k, v in key_map.items()}
        result = substitute(text, reverse_key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)
        highlight_english_words(result, self.output_text)

    def show_frequency_chart(self):
        output_text = self.output_text.get("1.0", tk.END).strip()
        if not output_text:
            messagebox.showwarning("警告", "请先生成输出文本")
            return

        freq = letter_frequency(output_text)
        letters = list(string.ascii_uppercase)
        output_freq = [freq.get(ch, 0) * 100 for ch in letters]
        english_freq = [ENGLISH_FREQ[ch] for ch in letters]

        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(letters, english_freq, label='English Avg', alpha=0.5, color='yellow')
        ax.bar(letters, output_freq, label='Output Text', alpha=0.7, color='grey')
        ax.set_title("Letter Frequency Comparison")
        ax.set_ylabel("Frequency (%)")
        ax.legend()

        freq_window = tk.Toplevel(self.root)
        freq_window.title("Frequency Analysis")
        canvas = FigureCanvasTkAgg(fig, master=freq_window)
        canvas.draw()
        canvas.get_tk_widget().pack()


if __name__ == "__main__":
    root = tk.Tk()
    app = SubstitutionApp(root)
    root.mainloop()
