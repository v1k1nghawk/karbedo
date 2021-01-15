#include "collisionAttackTask_CPU.h"
#include "user.h"


collisionAttackTask_CPU::collisionAttackTask_CPU(const Heuristic& heur, const uint& password_length, const QString& milestone) : QRunnable()
{
    this->m_heur = heur;

    if ((getUser() == Q_NULLPTR)
              || ((this->m_heur == Heuristic::partial) && (password_length > getOptimalMaxPL())))
        this->m_password_length = 0;
    else
        this->m_password_length = password_length;

    this->m_milestone = milestone;
}


// common settings
QQueue<QPair<QString, collisionAttackTask_CPU::Heuristic>> collisionAttackTask_CPU::m_milestonesFromCache;
QQueue<QPair<QString, collisionAttackTask_CPU::Heuristic>> collisionAttackTask_CPU::m_milestonesToCache;
QMutex collisionAttackTask_CPU::m_milestone_mutex;

QQueue<QString> collisionAttackTask_CPU::m_found_collisions;
QMutex collisionAttackTask_CPU::m_coll_mutex;

user* collisionAttackTask_CPU::m_target = Q_NULLPTR;
QString collisionAttackTask_CPU::m_algid_salt = QString("");
unsigned int collisionAttackTask_CPU::m_hits_num = 0;
QAtomicInt collisionAttackTask_CPU::m_attack_is_on = 0;


// "none" heuristic mode settings
const QVector<QString> collisionAttackTask_CPU::m_alphabet = {
"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f",
"g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v",
"w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L",
"M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_",".",
"-","!","@","*","$","?","&","%","\\","\"","#","'","(",")","+",",",
"/",":",";","[","]","^","`","{","|","}","~"," "
};


// "partial" heuristic mode settings
const QVector<QString> collisionAttackTask_CPU::m_part_alphabet = {
"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e",
"f","g","h","i","j","k","l","m","n","o","p","q","r","s","t",
"u","v","w","x","y","z","A","B","C","D","E","F","G","H","I",
"J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X",
"Y","Z","_",".","-","!","@","*","$","?","&","%"
};
const unsigned char collisionAttackTask_CPU::m_optimal_max_pass_length = 20;


const QVector<QString>* collisionAttackTask_CPU::getAlphabet(const Heuristic& heur)
{
    if (heur == Heuristic::none)
    {
        return &m_alphabet;

    } else if (heur == Heuristic::partial)
    {
        return &m_part_alphabet;
    }

    return Q_NULLPTR;
}


void collisionAttackTask_CPU::addCacheInit(const QString& thread_init, const Heuristic& thread_heur)
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    m_milestonesFromCache.enqueue(QPair<QString, Heuristic>(thread_init, thread_heur));
}


QPair<QString, collisionAttackTask_CPU::Heuristic> collisionAttackTask_CPU::getCacheInit()
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    if (m_milestonesFromCache.isEmpty())
        return QPair<QString, Heuristic>(QString(""), collisionAttackTask_CPU::Heuristic::none);
    return m_milestonesFromCache.dequeue();
}


void collisionAttackTask_CPU::addMilestone(const QString& thread_milestone, const Heuristic& thread_heur)
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    m_milestonesToCache.enqueue(QPair<QString, Heuristic>(thread_milestone, thread_heur));
}


QPair<QString, collisionAttackTask_CPU::Heuristic> collisionAttackTask_CPU::getMilestone()
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    if (m_milestonesToCache.isEmpty())
        return QPair<QString, Heuristic>(QString(""), collisionAttackTask_CPU::Heuristic::none);
    return m_milestonesToCache.dequeue();
}


void collisionAttackTask_CPU::clearCacheInit()
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    m_milestonesFromCache.clear();
}


void collisionAttackTask_CPU::clearMilestones()
{
    QMutexLocker milestones_locker(&m_milestone_mutex);
    m_milestonesToCache.clear();
}


void collisionAttackTask_CPU::addHit(const QString& new_finding)
{
    QMutexLocker hits_locker(&m_coll_mutex);
    m_found_collisions.enqueue(new_finding);
    m_hits_num++;
}


QString collisionAttackTask_CPU::getHit()
{
    QMutexLocker hits_locker(&m_coll_mutex);
    if (m_found_collisions.isEmpty())
        return QString("");
    return m_found_collisions.dequeue();
}


void collisionAttackTask_CPU::clearHits()
{
    QMutexLocker hits_locker(&m_coll_mutex);
    m_found_collisions.clear();
    m_hits_num = 0;
}


void collisionAttackTask_CPU::setNewTarget(user* const target)
{
    stopAttack();
    clearMilestones();
    clearHits();
    m_target = target;

    if (target == Q_NULLPTR)
    {
        m_algid_salt = QString("");
    }
    else
    {
        m_algid_salt = "$" + m_target->getAlgid() + "$" + m_target->getSalt();
        startAttack();
    }
}


void collisionAttackTask_CPU::run()
{
    QThread::currentThread()->setPriority(QThread::HighestPriority);

    if((attackStatus() != 1) ||
      ((m_heur != Heuristic::full) && (m_password_length == 0)))
        return;

    // attack
    if (m_heur == Heuristic::full)
    {
        // username attack
        if (m_milestone == "")
            evaluate_password(m_target->getName());

        // dictionary attack with "rockyou.txt"-type files
        dictionary_attack();

    } else if ((m_heur == Heuristic::partial) || (m_heur == Heuristic::none))
        brute_force();

    return;
}


bool collisionAttackTask_CPU::dictionary_attack()
{
    bool success_status = false;
    bool enable_evaluation = true;

    // check dictionaries' location
    QDir dict_dir(QDir::homePath() + QString("/.local/share/dictionaries/"));
    if(!dict_dir.exists())
        return success_status;

    // determine a reached milestone's properties in case of resumption of a suspended attack
    QString paused_filename="";
    uint paused_linenum=0;
    if (m_milestone != "")
    {
        QRegExp rxdelim("\\;");
        QStringList splittedMilestone = m_milestone.split(rxdelim);

        // check milestone's data integrity
        if (splittedMilestone.count() == 2)
        {
            paused_filename = splittedMilestone.at(0);
            bool linenum_ok = false;
            paused_linenum = splittedMilestone.at(1).toUInt(&linenum_ok);

            if (paused_filename != "" && linenum_ok)
            {
                // hold evaluation until reaching milestone (a specific line number in a specific dictionary file)
                enable_evaluation = false;
            }
        }
    }

    // evaluate all lines of all dictionaries (from the very begining or from reached milestone)
    QStringList dict_files = dict_dir.entryList(QStringList() << "*.txt" << "*.TXT",QDir::Files);
    foreach(QString filename, dict_files) {

        if (!(enable_evaluation || paused_filename == filename))
            continue;

        QFile dictFile(dict_dir.absolutePath() + "/" + filename);
        if (dictFile.open(QIODevice::ReadOnly))
        {
            uint linenum = 0;
            QString dicLine;

            QTextStream dic(&dictFile);
            while (!dic.atEnd())
            {
                dicLine = dic.readLine();

                if (!enable_evaluation && paused_linenum == linenum)
                    enable_evaluation = true;

                if (enable_evaluation)
                {
                    switch(attackStatus())
                    {
                        case 1:
                            // check for a collision
                            if (evaluate_password(dicLine) == true)
                                success_status = true;
                            break;
                        case 2:
                            // make savepoint and exit
                            addMilestone(QString(filename + ";" + QString::number(linenum)), m_heur);
                        default:
                            return success_status;
                    }
                }

                linenum++;
            }
            dictFile.close();
        }
    }

    return success_status;
}


bool collisionAttackTask_CPU::brute_force()
{
    bool success_status = false;

    if (m_password_length == 0)
        return success_status;

    QString current_pw;
    // take task's savepoint into account
    QString next_pw = initial_password(true, m_password_length);

    // loop through all possible passwords
    do {
        switch(attackStatus())
        {
            case 1:
                current_pw = next_pw;
                // check for a collision
                if (evaluate_password(current_pw) == true)
                    success_status = true;
                break;
            case 2:
                // make savepoint and exit
                addMilestone(next_pw, m_heur);
            default:
                return success_status;
        }
    }
    while (next_password(current_pw, next_pw) == 0);

    return success_status;
}


unsigned char collisionAttackTask_CPU::next_password(const QString& current_pass, QString& next_pass)
{
    next_pass = QString("");

    // check cardinality of a current password
    if (current_pass.length() != m_password_length)
    {
        next_pass = QString("");
        return 2;
    }

    // this thread's charset
    const QVector<QString>* work_alphabet = getAlphabet(m_heur);

    // check that current password's characters belongs to proper set
    for (auto character : current_pass)
    {
        if (! work_alphabet->contains(character))
            return 3;
    }

    // default rank of a changing character is the rightest position in the word
    int shift_position = current_pass.length() - 1;

    if(current_pass.at(shift_position) != work_alphabet->last()) // could lexicographically increase rightest position value
    {
        QString next_rightest_character = work_alphabet->at(work_alphabet->indexOf(current_pass.right(1)) + 1);
        // change only the rightest
        next_pass = current_pass.left(shift_position) + next_rightest_character;
    }
    else // could not
    {
        // determine changerank
        if (shift_position > 0) // multi-character word
        {
            for (int position = current_pass.length() - 2; position >= 0; position--)
            {
                if(current_pass.at(position) != work_alphabet->last())
                {
                    break;
                }
                shift_position--;
            }
        }

        // current password is the very last password
        if (shift_position == 0)
            return 1;

        // construct next password:
        // (a): keep leftest positions same
        if (shift_position - 1 >= 0)
            next_pass = current_pass.left(shift_position - 1);

        // (b): increase preshift position value
        QString preshift_value = work_alphabet->at(work_alphabet->indexOf(current_pass.at(shift_position - 1)) + 1);

        // and (c): set all shifting rightest positions to init values
        next_pass = next_pass + preshift_value + initial_password(false, current_pass.length() - shift_position);
    }

    work_alphabet = Q_NULLPTR;

    return 0;
}


QString collisionAttackTask_CPU::initial_password(const bool& use_task_milestone, const uint& length)
{
    const QVector<QString>* work_alphabet = getAlphabet(m_heur);

    QString password = QString("");

    if (use_task_milestone && m_milestone != "")
    {
        /////////////////////////////////
        // determine a reached milestone's properties in case of resumption of a suspended attack
        /////////////////////////////////

        // check that reached milestone's characters belongs to proper set
        bool milestone_ok = true;
        for (auto character : m_milestone)
        {
            if (! work_alphabet->contains(character))
                milestone_ok = false;
        }

        if (milestone_ok && (uint)m_milestone.size() == length)
            password = m_milestone;

    } else
    {
        // new (fresh) attack
        for (uint index = 0; index < length; index++)
            password.append(work_alphabet->first());
    }

    work_alphabet = Q_NULLPTR;

    return password;
}


bool collisionAttackTask_CPU::evaluate_password(const QString& password)
{
    // in a weak collision resistance sense
    bool hash_broken = false;

    // format from crypt(3) func: $id$salt$hash
    char* id_salt_hash = crypt(password.toLatin1().data(), m_algid_salt.toLatin1().data());

    QStringList splitted_id_salt_hash = QString::fromLocal8Bit(id_salt_hash).split("$");
    // discard crypt(3) possibly gibberish output
    if (splitted_id_salt_hash.length() < 4)
        return hash_broken;

    QString hash = splitted_id_salt_hash.at(3);

    if (compare_hashes(hash) == true)
    {
        addHit(password);
        hash_broken = true;
    }

    return hash_broken;
}


bool collisionAttackTask_CPU::compare_hashes(const QString& current_hash)
{
    bool collision_found = false;

    if (current_hash == m_target->getHash())
        collision_found = true;

    return collision_found;
}

