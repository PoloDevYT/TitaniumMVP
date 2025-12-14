const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./titanium.db');

const workouts = [
    {
        title: "Protocolo Hypertrophy Alpha",
        description: "Foco total em peitoral e tríceps com técnicas de drop-set.",
        difficulty: "Avançado",
        duration: "60 min",
        muscle_group: "Peito e Tríceps"
    },
    {
        title: "Leg Day Destruction",
        description: "Treino de alta intensidade para quadríceps e posterior.",
        difficulty: "Intermediário",
        duration: "50 min",
        muscle_group: "Pernas"
    },
    {
        title: "Back Widow Maker",
        description: "Construção de dorsais largas e bíceps densos.",
        difficulty: "Difícil",
        duration: "55 min",
        muscle_group: "Costas e Bíceps"
    },
    {
        title: "Shoulder Boulder",
        description: "Foco em deltoides laterais e desenvolvimento de força.",
        difficulty: "Intermediário",
        duration: "45 min",
        muscle_group: "Ombros"
    },
    {
        title: "Cardio HIIT Inferno",
        description: "Queima de gordura acelerada em 20 minutos.",
        difficulty: "Todos",
        duration: "20 min",
        muscle_group: "Cardio"
    },
    {
        title: "Abs de Titânio",
        description: "Rotina de core para estabilidade e definição.",
        difficulty: "Intermediário",
        duration: "15 min",
        muscle_group: "Abdômen"
    }
];

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS workouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        difficulty TEXT,
        duration TEXT,
        muscle_group TEXT
    )`);
    db.get("SELECT count(*) as count FROM workouts", (err, row) => {
        if (row.count === 0) {
            const stmt = db.prepare("INSERT INTO workouts (title, description, difficulty, duration, muscle_group) VALUES (?, ?, ?, ?, ?)");
            workouts.forEach(w => {
                stmt.run(w.title, w.description, w.difficulty, w.duration, w.muscle_group);
            });
            stmt.finalize();
            console.log("Workouts seeded successfully.");
        } else {
            console.log("Workouts table already populated.");
        }
    });
});

db.close();
