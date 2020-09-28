#ifndef SHADOWPARSINGEXCEPTION_H
#define SHADOWPARSINGEXCEPTION_H

#include <QException>


/**
 * @class ShadowParsingException
 * @brief Raise in case of incompatible shadow file format.
 */
class ShadowParsingException : public QException
{
public:
    ShadowParsingException(const QString& err_text=" ") noexcept : err_msg(err_text) {}
    ShadowParsingException(const ShadowParsingException& re) {this->err_msg = re.err_msg; }
    ~ShadowParsingException() override {}

    void raise() const override { throw *this; }
    ShadowParsingException *clone() const override { return new ShadowParsingException(*this); }
    const char *what() const noexcept override { return this->err_msg.toStdString().c_str(); }

private:
    QString err_msg;
};







#endif // SHADOWPARSINGEXCEPTION_H
