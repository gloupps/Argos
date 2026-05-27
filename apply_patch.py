"""
Script à exécuter UNE FOIS à la racine du projet :
    python apply_patch.py

Il modifie app/services/routes.py en place.
"""
import pathlib, sys

path = pathlib.Path("app/services/routes.py")
if not path.exists():
    sys.exit(f"Fichier introuvable : {path}")

src = path.read_text()

# ── patch 1a : SELECT id → SELECT id, name ──
old = '"SELECT id FROM cases WHERE id=?", (existing_id,)'
new = '"SELECT id, name FROM cases WHERE id=?", (existing_id,)'
assert old in src, "Patch 1a introuvable — déjà appliqué ?"
src = src.replace(old, new, 1)

# ── patch 1b : return None, f"Case…" → return None, None, f"Case…" ──
old = '                return None, f"Case {existing_id} not found"\n            return row["id"], None'
new = '                return None, None, f"Case {existing_id} not found"\n            return row["id"], row["name"], None'
assert old in src, "Patch 1b introuvable — déjà appliqué ?"
src = src.replace(old, new, 1)

# ── patch 1c : return case_id, None  (fin du try) ──
old = '        return case_id, None\n    except Exception as e:\n        conn.rollback()\n        return None, str(e)'
new = '        return case_id, case_name, None\n    except Exception as e:\n        conn.rollback()\n        return None, None, str(e)'
assert old in src, "Patch 1c introuvable — déjà appliqué ?"
src = src.replace(old, new, 1)

# ── patch 2a : déstructuration dans api_run ──
old = '            case_id, err = _handle_create_case(db_path, data)'
new = '            case_id, resolved_name, err = _handle_create_case(db_path, data)'
assert old in src, "Patch 2a introuvable — déjà appliqué ?"
src = src.replace(old, new, 1)

# ── patch 2b : jsonify de retour ──
old = '            return jsonify({"case_id": case_id, "job_ids": job_ids})'
new = '            return jsonify({"case_id": case_id, "case_name": resolved_name, "job_ids": job_ids})'
assert old in src, "Patch 2b introuvable — déjà appliqué ?"
src = src.replace(old, new, 1)

path.write_text(src)
print("✅ routes.py patché avec succès")
