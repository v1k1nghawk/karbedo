#include "collisionAttackTask_CPU.h"
#include "user.h"


collisionAttackTask_CPU::collisionAttackTask_CPU(const Heuristics& heur, const unsigned int password_length) : QRunnable()
{
    this->m_heur = heur;

    if ((getUser() == Q_NULLPTR)
              || ((this->m_heur == Heuristics::partial) && (password_length > getOptimalMaxPL())))
        this->m_password_length = 0;
    else
        this->m_password_length = password_length;
}


// common settings
QQueue<QString> collisionAttackTask_CPU::m_found_collisions;
QMutex collisionAttackTask_CPU::m_coll_mutex;
user* collisionAttackTask_CPU::m_target = Q_NULLPTR;
QString collisionAttackTask_CPU::m_algid_salt = QString("");
unsigned int collisionAttackTask_CPU::m_hits_num = 0;
QAtomicInt collisionAttackTask_CPU::m_attack_is_on = 0;


// "none" heuristics mode settings
const QVector<QString> collisionAttackTask_CPU::m_alphabet = {
"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f",
"g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v",
"w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L",
"M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_",".",
"-","!","@","*","$","?","&","%","\\","\"","#","'","(",")","+",",",
"/",":",";","[","]","^","`","{","|","}","~"," "
};


// "partial" heuristics mode settings
const QVector<QString> collisionAttackTask_CPU::m_part_alphabet = {
"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e",
"f","g","h","i","j","k","l","m","n","o","p","q","r","s","t",
"u","v","w","x","y","z","A","B","C","D","E","F","G","H","I",
"J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X",
"Y","Z","_",".","-","!","@","*","$","?","&","%"
};
const unsigned char collisionAttackTask_CPU::m_optimal_max_pass_length = 20;


const QVector<QString>* collisionAttackTask_CPU::getAlphabet(const Heuristics& heur)
{
    if (heur == Heuristics::none)
    {
        return &m_alphabet;

    } else if (heur == Heuristics::partial)
    {
        return &m_part_alphabet;
    }

    return Q_NULLPTR;
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
    clearHits();
    m_target = target;

    if (target == Q_NULLPTR)
    {
        m_algid_salt = QString("");
    }
    else
    {
        m_algid_salt = "$" + m_target->getUseralgid() + "$" + m_target->getUsersalt();
        m_attack_is_on.store(1);
    }
}


void collisionAttackTask_CPU::run()
{
    QThread::currentThread()->setPriority(QThread::HighestPriority);

    if((attackStatus() == false)
            || ((m_heur != Heuristics::full) && (m_password_length == 0)))
        return;

    // attack
    if (m_heur == Heuristics::full)
    {
        // username attack
        evaluate_password(m_target->getUsername());

        // TO DO: dictionary attack with rockyou.txt


    } else if ((m_heur == Heuristics::partial) || (m_heur == Heuristics::none))
    {
        brute_force();
    }

    return;
}


bool collisionAttackTask_CPU::brute_force()
{
    bool success = false;

    if (m_password_length == 0)
        return success;

    QString current_pw;
    QString next_pw = initial_password(m_password_length);

    // loop through all possible passwords
    do {
        if(attackStatus() == false)
            return success;

        current_pw = next_pw;
        // check for a collision
        if (evaluate_password(current_pw) == true)
            success = true;
    }
    while (next_password(current_pw, next_pw) == 0);

    return success;
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
        next_pass = next_pass + preshift_value + initial_password(current_pass.length() - shift_position);
    }

    return 0;
}


QString collisionAttackTask_CPU::initial_password(const uint& length)
{
    const QVector<QString>* work_alphabet = getAlphabet(m_heur);

    QString password = QString("");

    for (uint index = 0; index < length; index++)
        password.append(work_alphabet->first());

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

    if (current_hash == m_target->getUserhash())
        collision_found = true;

    return collision_found;
}
