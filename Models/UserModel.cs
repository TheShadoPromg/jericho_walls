using FluentValidation;
using Newtonsoft.Json;
using System;
using System.Linq;

namespace rde.edu.do_jericho_walls.Models
{
    public class UserModel
    {
        public int Id { get; set; }
        public Guid Identifier { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }

        public int TokenDuration { get; set; }
        public bool Active { get; set; }
    }

    public class UserModelValidator : AbstractValidator<UserModel>
    {
        public UserModelValidator()
        {
            RuleFor(m => m.FirstName)
                .Cascade(CascadeMode.StopOnFirstFailure)
                .NotEmpty().WithMessage("El {PropertyName} es requerido")
                .Length(2, 96).WithMessage("El {PropertyName} debe tener mínimo {MinLength} y máximo {MaxLength}. El {PropertyName} tiene una longitud de {TotalLength}")
                .Must(ValidName).WithMessage("El {PropertyName} contiene caracteres inválidos.")
                .WithName("nombre");

            RuleFor(m => m.LastName)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("El {PropertyName} es requerido")
               .Length(2, 96).WithMessage("El {PropertyName} debe tener mínimo {MinLength} y máximo {MaxLength}. El {PropertyName} tiene una longitud de {TotalLength}")
               .Must(ValidName).WithMessage("El {PropertyName} contiene caracteres inválidos.")
               .WithName("apellido");

            RuleFor(m => m.Email)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("El {PropertyName} es requerido.")
               .EmailAddress().WithMessage("El {PropertyName} es invalido.")
               .WithName("correo electrónico");

            RuleFor(m => m.Password)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("La {PropertyName} es requerida.")
               .Length(8, -1).WithMessage("La {PropertyName} debe tener mínimo {MinLength} caracteres. La {PropertyName} tiene una longitud de {TotalLength}")
               .Must(ValidPassword).WithMessage("La {PropertyName} debe tener mínimo un dígito, una letra mayúscula y otra minúscula.")
               .WithName("contraseña");

            RuleFor(m => m.TokenDuration)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("La {PropertyName} es requerida.")
               .GreaterThanOrEqualTo(1).WithMessage("La {PropertyName} debe ser igual o mayor que {ComparisonValue}.")
               .WithName("duración del token");

            RuleFor(m => m.Active)
              .Cascade(CascadeMode.StopOnFirstFailure)
              .NotNull().WithMessage("El {PropertyName} es requerida.")
              .WithName("estado de la cuenta");
        }

        protected bool ValidName(string name)
        {
            name = name.Trim();
            name = name.Replace(" ", "");
            return name.All(Char.IsLetter);
        }

        static bool ValidPassword(string password)
        {
            bool hasUpperCaseLetter = false;
            bool hasLowerCaseLetter = false;
            bool hasDecimalDigit = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpperCaseLetter = true;
                else if (char.IsLower(c)) hasLowerCaseLetter = true;
                else if (char.IsDigit(c)) hasDecimalDigit = true;
            }

            return hasUpperCaseLetter && hasLowerCaseLetter && hasDecimalDigit;
        }
    }
}
