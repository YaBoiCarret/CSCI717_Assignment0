Aristocrat Solver - Claude Final Version

This solver cracks monoalphabetic substitution ciphers (Aristocrats). It includes Claude’s improvements: adaptive swaps (mostly 2-swaps, sometimes 3-cycles), pattern-aware scoring (bonuses for I/A, contractions, penalties for unlikely singles), and a better seed that locks the most common bigram as TH.

Requirements: Python 3.8+ with standard libraries only.

Usage:
Run with inline ciphertext:
python3 aristocrat_solver_combined_betterseed.py --cipher "YOUR CIPHERTEXT" --restarts 40 --steps 20000 --seed 123

Run with file input:
python3 aristocrat_solver_combined_betterseed.py --file cipher.txt --restarts 40 --steps 20000 --seed 123

Options:
--cipher : ciphertext as a string
--file : path to file containing ciphertext
--steps : annealing steps per restart (default 8000)
--restarts : number of restarts (default 25)
--seed : random seed for reproducibility

Output:
The solver prints the best score, the key mapping, and the plaintext guess. Longer runs and multiple seeds often improve results. Use fixed seeds if you need reproducibility.
