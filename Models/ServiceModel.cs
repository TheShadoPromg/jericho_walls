using FluentValidation;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace rde.edu.do_jericho_walls.Models
{
    public class ServiceModel
    {
        public int Id { get; set; }
        public Guid Identifier { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Host { get; set; }
        public int Port { get; set; }
        [JsonProperty("public_key")]
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public bool Active { get; set; }
        [JsonProperty("created_by")]
        public string CreatedBy { get; set; }
        public IList<string> Permissions { get; set; }

        public ServiceModel()
        {
            Permissions = new List<string>();
        }
    }

    public class ServiceModelValidator : AbstractValidator<ServiceModel>
    {
        public ServiceModelValidator(bool update = false)
        {
            if (!update)
            {
                RuleFor(m => m.Name)
                    .Cascade(CascadeMode.StopOnFirstFailure)
                    .NotEmpty().WithMessage("El {PropertyName} es requerido")
                    .Length(2, 45).WithMessage("El {PropertyName} debe tener mínimo {MinLength} y máximo {MaxLength} caracteres. El {PropertyName} tiene una longitud de {TotalLength} caracteres.")
                    .Must(ValidName).WithMessage("El {PropertyName} contiene caracteres inválidos.")
                    .WithName("nombre");
            }

            RuleFor(m => m.Description)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("La {PropertyName} es requerido")
               .Length(50, 255).WithMessage("La {PropertyName} debe tener mínimo {MinLength} y máximo {MaxLength} caracteres. El {PropertyName} tiene una longitud de {TotalLength} caracteres.")
               .Must(ValidName).WithMessage("La {PropertyName} contiene caracteres inválidos.")
               .WithName("descripción");

            RuleFor(m => m.Host)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("El {PropertyName} es requerido")
               .Length(2, 255).WithMessage("El {PropertyName} debe tener mínimo {MinLength} y máximo {MaxLength} caracteres. El {PropertyName} tiene una longitud de {TotalLength} caracteres.")
                .Must(ValidHost).WithMessage("El {PropertyName} es invalido.")
               .WithName("host");

            RuleFor(m => m.Port)
                .Cascade(CascadeMode.StopOnFirstFailure)
                .NotEmpty().WithMessage("El {PropertyName} es requerido")
                .InclusiveBetween(1, 65535).WithMessage("El {PropertyName} debe tener mínimo 1 y máximo 65535 caracteres. El {PropertyName} tiene un valor de {PropertyValue}.")
                .WithName("puerto");

            RuleFor(m => m.Active)
             .Cascade(CascadeMode.StopOnFirstFailure)
             .NotNull().WithMessage("El {PropertyName} es requerida.")
             .WithName("estado del servicio");
        }

        protected bool ValidName(string name)
        {
            name = name.Trim();
            name = name.Replace(" ", "");
            name = name.Replace("-", "");
            name = name.Replace("_", "");
            name = name.Replace(",", "");
            name = name.Replace(".", "");
            return name.All(Char.IsLetterOrDigit);
        }

        protected bool ValidHost(string name)
        {
            return Uri.CheckHostName(name) != UriHostNameType.Unknown;
        }
    }
}
